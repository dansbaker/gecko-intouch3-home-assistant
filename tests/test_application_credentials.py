"""Verify the HA-managed application-credentials route and Gecko PKCE semantics."""

from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.components.application_credentials import (
    ClientCredential,
    async_import_client_credential,
)
from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry
from yarl import URL

from custom_components.gecko.application_credentials import (
    async_get_auth_implementation,
)
from custom_components.gecko.const import API_BASE_URL, OAUTH2_CLIENT_ID


@pytest.mark.parametrize("name", [None, "My registered Gecko app"])
async def test_credential_identity_pkce_and_authorize_parameters(hass, name):
    hass.config.components.add("my")
    credential = ClientCredential("user-client", "user-secret", name=name)
    impl = await async_get_auth_implementation(hass, "gecko.user-client", credential)
    assert impl.domain == "gecko.user-client"
    assert impl.name == (name or "user-client")
    url = URL(await impl.async_generate_authorize_url("test-flow"))
    assert url.query["client_id"] == "user-client"
    assert url.query["redirect_uri"] == "https://my.home-assistant.io/redirect/oauth"
    assert url.query["audience"] == API_BASE_URL
    assert "offline_access" in url.query["scope"]
    assert url.query["code_challenge_method"] == "S256"
    verifier = impl.extra_token_resolve_data["code_verifier"]
    assert url.query["code_challenge"] == impl.compute_code_challenge(verifier)
    assert "user-secret" not in str(url)
    assert verifier not in str(url)
    assert impl.client_secret == "user-secret"


@pytest.fixture
async def credentials(hass, enable_custom_integrations):
    hass.config.components.add("my")
    assert await async_setup_component(hass, "application_credentials", {})
    await async_import_client_credential(
        hass,
        "gecko",
        ClientCredential("user-client", "user-secret", name="My Gecko app"),
        auth_domain="gecko.user-client",
    )


async def test_stored_credentials_and_existing_public_client_coexist(hass, credentials):
    with patch(
        "custom_components.gecko.async_setup_entry", AsyncMock(return_value=True)
    ):
        result = await hass.config_entries.flow.async_init(
            "gecko", context={"source": "user"}
        )
    implementations = await config_entry_oauth2_flow.async_get_implementations(
        hass, "gecko"
    )
    assert result["step_id"] == "pick_implementation"
    assert implementations["gecko.user-client"].client_id == "user-client"
    assert implementations["gecko.user-client"].name == "My Gecko app"
    assert implementations["gecko"].client_id == OAUTH2_CLIENT_ID
    # Older entries retain their original provider instead of silently using new credentials.
    legacy = MockConfigEntry(domain="gecko", data={"auth_implementation": "gecko"})
    assert (
        await config_entry_oauth2_flow.async_get_config_entry_implementation(
            hass, legacy
        )
    ).client_id == OAUTH2_CLIENT_ID
    hass.config_entries.flow.async_abort(result["flow_id"])


async def test_application_credential_flow_records_selected_provider(hass, credentials):
    token = {
        "access_token": "new-access",
        "refresh_token": "new-refresh",
        "expires_in": 3600,
    }
    with (
        patch(
            "custom_components.gecko.config_flow.ConfigFlowGeckoApi", autospec=True
        ) as api_cls,
        patch(
            "custom_components.gecko.oauth_implementation.GeckoPKCEOAuth2Implementation.async_resolve_external_data",
            AsyncMock(return_value=token),
        ),
        patch(
            "custom_components.gecko.async_setup_entry", AsyncMock(return_value=True)
        ),
    ):
        api = api_cls.return_value
        api.async_get_user_id.return_value = "user"
        api.async_get_user_info.return_value = {"account": {"accountId": "account"}}
        api.async_get_vessels.return_value = []
        result = await hass.config_entries.flow.async_init(
            "gecko", context={"source": "user"}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"implementation": "gecko.user-client"}
        )
        assert URL(result["url"]).query["client_id"] == "user-client"
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"code": "app-code"}
        )
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
        assert result["result"].unique_id == "account"
        assert result["data"]["auth_implementation"] == "gecko.user-client"
        assert "client_secret" not in result["data"]
        await hass.async_block_till_done()


@pytest.mark.parametrize("secret", ["", "user-secret"])
async def test_real_code_exchange_uses_selected_client_and_pkce(
    hass, aioclient_mock, secret
):
    from custom_components.gecko.const import OAUTH2_TOKEN

    impl = await async_get_auth_implementation(
        hass, "gecko.user-client", ClientCredential("user-client", secret)
    )
    aioclient_mock.post(
        OAUTH2_TOKEN,
        json={"access_token": "access", "refresh_token": "refresh", "expires_in": 3600},
    )
    token = await impl.async_resolve_external_data(
        {
            "code": "app-code",
            "state": {"redirect_uri": "https://my.home-assistant.io/redirect/oauth"},
        }
    )
    assert token["refresh_token"] == "refresh"
    data = aioclient_mock.mock_calls[-1][2]
    assert data["client_id"] == "user-client"
    assert data["code_verifier"] == impl.code_verifier
    assert data["grant_type"] == "authorization_code"
    assert data["redirect_uri"] == "https://my.home-assistant.io/redirect/oauth"
    if secret:
        assert data["client_secret"] == secret
    else:
        assert "client_secret" not in data


async def test_refresh_uses_application_credentials_and_preserves_entry_data(
    hass, aioclient_mock
):
    from custom_components.gecko.api import OAuthGeckoApi
    from custom_components.gecko.const import OAUTH2_TOKEN

    impl = await async_get_auth_implementation(
        hass, "gecko.user-client", ClientCredential("user-client", "secret")
    )
    entry = MockConfigEntry(
        domain="gecko",
        data={
            "auth_implementation": "gecko.user-client",
            "account_id": "account",
            "vessels": [{"vesselId": "spa"}],
            "token": {
                "access_token": "old",
                "refresh_token": "keep-refresh",
                "expires_at": 0,
            },
        },
    )
    entry.add_to_hass(hass)
    # OAuth providers may omit refresh_token during renewal. HA must retain it.
    aioclient_mock.post(OAUTH2_TOKEN, json={"access_token": "new", "expires_in": 3600})
    api = OAuthGeckoApi(hass, config_entry_oauth2_flow.OAuth2Session(hass, entry, impl))
    assert await api.async_get_access_token() == "new"
    assert entry.data["token"]["refresh_token"] == "keep-refresh"
    assert entry.data["auth_implementation"] == "gecko.user-client"
    assert entry.data["vessels"] == [{"vesselId": "spa"}]
    data = aioclient_mock.mock_calls[-1][2]
    assert data == {
        "grant_type": "refresh_token",
        "client_id": "user-client",
        "client_secret": "secret",
        "refresh_token": "keep-refresh",
    }
    assert await api.async_get_access_token() == "new"
    assert aioclient_mock.call_count == 1


@pytest.mark.parametrize("status", [400, 429, 503])
async def test_refresh_failures_reauthenticate_only_for_invalid_credentials(
    hass, credentials, aioclient_mock, status
):
    from homeassistant.exceptions import ConfigEntryAuthFailed
    from homeassistant.helpers.config_entry_oauth2_flow import (
        OAuth2TokenRequestTransientError,
    )

    from custom_components.gecko.api import OAuthGeckoApi
    from custom_components.gecko.const import OAUTH2_TOKEN

    impl = await async_get_auth_implementation(
        hass, "gecko.user-client", ClientCredential("user-client", "secret")
    )
    entry = MockConfigEntry(
        domain="gecko",
        data={
            "auth_implementation": "gecko.user-client",
            "account_id": "account",
            "token": {
                "access_token": "old",
                "refresh_token": "refresh",
                "expires_at": 0,
            },
        },
    )
    entry.add_to_hass(hass)
    aioclient_mock.post(
        OAUTH2_TOKEN,
        status=status,
        json={"error": "invalid_grant" if status == 400 else "unavailable"},
    )
    api = OAuthGeckoApi(hass, config_entry_oauth2_flow.OAuth2Session(hass, entry, impl))
    with pytest.raises(
        ConfigEntryAuthFailed if status == 400 else OAuth2TokenRequestTransientError
    ):
        await api.async_get_access_token()
    await hass.async_block_till_done()
    assert entry.data["token"]["access_token"] == "old"
    assert bool(hass.config_entries.flow.async_progress()) == (status == 400)
