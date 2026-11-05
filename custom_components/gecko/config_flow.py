"""Config flow for Gecko."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from aiohttp import ClientError, ClientResponseError
from homeassistant.config_entries import SOURCE_REAUTH, ConfigFlowResult
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import config_entry_oauth2_flow

from .api import ConfigFlowGeckoApi
from .const import DOMAIN, OAUTH2_AUTHORIZE, OAUTH2_CLIENT_ID, OAUTH2_TOKEN
from .oauth_implementation import GeckoPKCEOAuth2Implementation

_LOGGER = logging.getLogger(__name__)


class ConfigFlow(config_entry_oauth2_flow.AbstractOAuth2FlowHandler, domain=DOMAIN):
    """Handle Gecko account setup with retryable API validation."""

    DOMAIN = DOMAIN
    VERSION = 1
    _oauth_data: dict[str, Any]
    _reauthorize_required = False

    async def async_step_user(self, user_input=None) -> ConfigFlowResult:
        """Start OAuth while retaining the working custom-integration login."""
        await self.async_register_implementation()
        return await super().async_step_user(user_input)

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Confirm before asking the user to authenticate again."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None) -> ConfigFlowResult:
        """Keep existing data until the same account authenticates successfully."""
        if user_input is None:
            return self.async_show_form(
                step_id="reauth_confirm", data_schema=vol.Schema({})
            )
        return await self.async_step_user()

    async def async_oauth_create_entry(self, data: dict) -> ConfigFlowResult:
        """Validate Gecko account access before creating or updating an entry."""
        self._oauth_data = data
        self._reauthorize_required = False
        return await self.async_step_account()

    async def async_step_account(self, user_input=None) -> ConfigFlowResult:
        """Retry failed account validation without discarding a valid login."""
        if user_input is not None and self._reauthorize_required:
            return await self.async_step_user()

        token = self._oauth_data.get("token", {})
        error = "cannot_connect"
        if not token.get("access_token") or not token.get("refresh_token"):
            self._reauthorize_required = True
        else:
            api_client = ConfigFlowGeckoApi(self.hass, token["access_token"])
            try:
                async with asyncio.timeout(15):
                    user_id, account, account_id = await self._resolve_user_and_account(
                        self._oauth_data, api_client
                    )
                    # Reauth must not replace the existing vessel/configuration snapshot.
                    vessels = (
                        None
                        if self.source == SOURCE_REAUTH
                        else await api_client.async_get_vessels(account_id)
                    )
                    if self.source != SOURCE_REAUTH and (
                        not isinstance(vessels, list)
                        or any(not isinstance(vessel, dict) for vessel in vessels)
                    ):
                        raise ValueError("Invalid vessel list returned by Gecko")
            except ConfigEntryAuthFailed:
                self._reauthorize_required = True
            except ClientResponseError as err:
                self._reauthorize_required = err.status in (401, 403)
            except OSError, ValueError, TypeError, ClientError:
                _LOGGER.debug("Gecko account validation failed", exc_info=True)
            else:
                return await self._async_finish_account(
                    api_client, user_id, account, account_id, vessels
                )
        if self._reauthorize_required:
            error = "invalid_auth"
        return self.async_show_form(
            step_id="account", data_schema=vol.Schema({}), errors={"base": error}
        )

    async def _async_finish_account(
        self, api_client, user_id, account, account_id, vessels
    ) -> ConfigFlowResult:
        """Finish only after successful validation; duplicate aborts propagate."""
        if self.source == SOURCE_REAUTH:
            entry = self._get_reauth_entry()
            if str(entry.data.get("account_id")) != account_id:
                return self.async_abort(reason="wrong_account")
            return self.async_update_reload_and_abort(
                entry, data={**entry.data, **self._oauth_data}
            )

        await self.async_set_unique_id(account_id)
        self._abort_if_unique_id_configured()
        # Older entries have no unique_id and may store an integer account ID.
        if any(
            str(entry.data.get("account_id")) == account_id
            for entry in self._async_current_entries()
        ):
            return self.async_abort(reason="already_configured")

        vessels_with_config = []
        for vessel in vessels:
            monitor_id = vessel.get("monitorId") or vessel.get("vesselId")
            if monitor_id:
                try:
                    async with asyncio.timeout(15):
                        configuration = await api_client.async_get_spa_configuration(
                            account_id, str(monitor_id)
                        )
                    vessel = {**vessel, "spa_configuration": configuration}
                except OSError, ValueError, TypeError, ClientError:
                    # Optional metadata must not prevent using valid account/vessel data.
                    _LOGGER.debug(
                        "Optional spa configuration unavailable", exc_info=True
                    )
            vessels_with_config.append(vessel)
        return self.async_create_entry(
            title=f"Gecko - {account.get('name', 'Account')} ({len(vessels_with_config)} vessels)",
            data={
                **self._oauth_data,
                "vessels": vessels_with_config,
                "account_id": account_id,
                "user_id": user_id,
                "account_info": account,
            },
        )

    async def async_register_implementation(self) -> None:
        """Register the existing PKCE implementation once."""
        implementations = await config_entry_oauth2_flow.async_get_implementations(
            self.hass, DOMAIN
        )
        if DOMAIN not in implementations:
            config_entry_oauth2_flow.async_register_implementation(
                self.hass,
                DOMAIN,
                GeckoPKCEOAuth2Implementation(
                    self.hass,
                    DOMAIN,
                    client_id=OAUTH2_CLIENT_ID,
                    authorize_url=OAUTH2_AUTHORIZE,
                    token_url=OAUTH2_TOKEN,
                ),
            )

    async def _resolve_user_and_account(
        self, data: dict, api_client
    ) -> tuple[str, dict, str]:
        """Require real stable account identity, never the string 'None'."""
        user_id = await api_client.async_get_user_id()
        user_data = await api_client.async_get_user_info(user_id)
        account = user_data.get("account") if isinstance(user_data, dict) else None
        if not isinstance(account, dict):
            raise TypeError("No account returned by Gecko")
        identifier = account.get("accountId")
        if (
            not user_id
            or isinstance(identifier, bool)
            or not isinstance(identifier, (str, int))
            or not str(identifier).strip()
        ):
            raise ValueError("No valid user/account identity returned by Gecko")
        return user_id, account, str(identifier).strip()

    @property
    def logger(self) -> logging.Logger:
        """Return the flow logger."""
        return _LOGGER
