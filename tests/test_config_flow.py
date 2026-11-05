"""Exercise Gecko configuration through Home Assistant's flow manager."""

from unittest.mock import AsyncMock, patch

import pytest
from aiohttp import ClientResponseError, ServerDisconnectedError
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

DOMAIN = "gecko"
TOKEN = {"access_token": "access", "refresh_token": "refresh", "expires_in": 3600}


@pytest.fixture(autouse=True)
def custom_integrations(hass, enable_custom_integrations):
    """Load the actual flow without requiring the unrelated frontend package."""
    hass.config.components.add("my")


@pytest.fixture
def api():
    with patch(
        "custom_components.gecko.config_flow.ConfigFlowGeckoApi", autospec=True
    ) as cls:
        api = cls.return_value
        api.async_get_user_id.return_value = "user"
        api.async_get_user_info.return_value = {
            "account": {"accountId": "account", "name": "Home"}
        }
        api.async_get_vessels.return_value = [
            {"vesselId": "spa", "monitorId": "monitor", "name": "Spa"}
        ]
        api.async_get_spa_configuration.return_value = {"zones": {}}
        yield api


@pytest.fixture
def oauth():
    with (
        patch(
            "custom_components.gecko.oauth_implementation.GeckoPKCEOAuth2Implementation.async_generate_authorize_url",
            AsyncMock(return_value="https://example.com/authorize"),
        ),
        patch(
            "custom_components.gecko.oauth_implementation.GeckoPKCEOAuth2Implementation.async_resolve_external_data",
            AsyncMock(return_value=TOKEN.copy()),
        ) as resolve,
        patch(
            "custom_components.gecko.async_setup_entry", AsyncMock(return_value=True)
        ),
    ):
        yield resolve


async def finish_login(hass, result):
    """Select the registered PKCE login and deliver its external callback."""
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "pick_implementation"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"implementation": DOMAIN}
    )
    assert result["type"] is FlowResultType.EXTERNAL_STEP
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"code": "code"}
    )
    assert result["type"] is FlowResultType.EXTERNAL_STEP_DONE
    return await hass.config_entries.flow.async_configure(result["flow_id"], {})


async def begin(hass):
    return await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})


async def test_success_sets_stable_account_identity(hass, api, oauth):
    result = await finish_login(hass, await begin(hass))
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].unique_id == "account"
    assert result["data"]["vessels"][0]["spa_configuration"] == {"zones": {}}
    assert result["data"]["account_id"] == "account"
    assert result["data"]["token"]["refresh_token"] == "refresh"
    await hass.async_block_till_done()


@pytest.mark.parametrize(
    "legacy,account", [(False, "account"), (True, "account"), (True, 123)]
)
async def test_duplicate_account_is_rejected_including_legacy_entries(
    hass, api, oauth, legacy, account
):
    api.async_get_user_info.return_value = {"account": {"accountId": account}}
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=None if legacy else str(account),
        data={"account_id": account, "token": {"access_token": "old"}},
    )
    entry.add_to_hass(hass)
    result = await finish_login(hass, await begin(hass))
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
    assert entry.data["token"]["access_token"] == "old"
    api.async_get_spa_configuration.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        OSError("offline"),
        TimeoutError(),
        ServerDisconnectedError(),
        ClientResponseError(None, (), status=429),
    ],
)
async def test_account_failure_recovers_without_another_oauth_login(
    hass, api, oauth, failure
):
    api.async_get_vessels.side_effect = failure
    result = await finish_login(hass, await begin(hass))
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "cannot_connect"}
    api.async_get_vessels.side_effect = None
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].unique_id == "account"
    assert oauth.await_count == 1
    await hass.async_block_till_done()


@pytest.mark.parametrize("identifier", [None, "", " ", True, [], {}])
async def test_invalid_identity_recovers(hass, api, oauth, identifier):
    api.async_get_user_info.return_value = {"account": {"accountId": identifier}}
    result = await finish_login(hass, await begin(hass))
    assert result["errors"] == {"base": "cannot_connect"}
    api.async_get_user_info.return_value = {"account": {"accountId": "account"}}
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].unique_id == "account"
    await hass.async_block_till_done()


@pytest.mark.parametrize("status", [401, 403])
async def test_invalid_api_auth_restarts_login_then_recovers(hass, api, oauth, status):
    api.async_get_user_id.side_effect = ClientResponseError(None, (), status=status)
    result = await finish_login(hass, await begin(hass))
    assert result["errors"] == {"base": "invalid_auth"}
    api.async_get_user_id.side_effect = None
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    result = await finish_login(hass, result)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].unique_id == "account"
    await hass.async_block_till_done()


@pytest.mark.parametrize("missing", ["refresh_token", "access_token"])
async def test_incomplete_token_cannot_create_unusable_entry(hass, api, oauth, missing):
    oauth.return_value = {k: v for k, v in TOKEN.items() if k != missing}
    result = await finish_login(hass, await begin(hass))
    assert result["errors"] == {"base": "invalid_auth"}
    api.async_get_user_id.assert_not_awaited()
    oauth.return_value = TOKEN.copy()
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    result = await finish_login(hass, result)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].unique_id == "account"
    await hass.async_block_till_done()


@pytest.mark.parametrize(
    "vessels", [[], [{"vesselId": "fallback"}], [{"name": "No identifier"}]]
)
async def test_empty_accounts_and_vessels_without_monitor_id(hass, api, oauth, vessels):
    api.async_get_vessels.return_value = vessels
    result = await finish_login(hass, await begin(hass))
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].unique_id == "account"
    assert len(result["data"]["vessels"]) == len(vessels)
    if vessels and "vesselId" in vessels[0]:
        api.async_get_spa_configuration.assert_awaited_once_with("account", "fallback")
    else:
        api.async_get_spa_configuration.assert_not_awaited()
    await hass.async_block_till_done()


async def test_optional_configuration_failure_does_not_hide_spa(hass, api, oauth):
    api.async_get_spa_configuration.side_effect = TimeoutError()
    result = await finish_login(hass, await begin(hass))
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].unique_id == "account"
    assert result["data"]["vessels"] == api.async_get_vessels.return_value
    await hass.async_block_till_done()


@pytest.mark.parametrize("payload", [None, {}, {"account": None}])
async def test_malformed_user_response_can_be_retried(hass, api, oauth, payload):
    api.async_get_user_info.return_value = payload
    result = await finish_login(hass, await begin(hass))
    assert result["errors"] == {"base": "cannot_connect"}
    api.async_get_user_info.return_value = {"account": {"accountId": "account"}}
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["result"].unique_id == "account"
    await hass.async_block_till_done()


async def test_missing_user_identity_can_be_retried(hass, api, oauth):
    api.async_get_user_id.return_value = ""
    result = await finish_login(hass, await begin(hass))
    assert result["errors"] == {"base": "cannot_connect"}
    api.async_get_user_id.return_value = "user"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["result"].unique_id == "account"
    await hass.async_block_till_done()


@pytest.mark.parametrize("payload", [None, {}, [None]])
async def test_malformed_vessels_can_be_retried(hass, api, oauth, payload):
    api.async_get_vessels.return_value = payload
    result = await finish_login(hass, await begin(hass))
    assert result["errors"] == {"base": "cannot_connect"}
    api.async_get_vessels.return_value = []
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["result"].unique_id == "account"
    await hass.async_block_till_done()


async def test_auth_exception_can_be_retried(hass, api, oauth):
    from homeassistant.exceptions import ConfigEntryAuthFailed

    api.async_get_user_id.side_effect = ConfigEntryAuthFailed()
    result = await finish_login(hass, await begin(hass))
    assert result["errors"] == {"base": "invalid_auth"}
    api.async_get_user_id.side_effect = None
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    result = await finish_login(hass, result)
    assert result["result"].unique_id == "account"
    await hass.async_block_till_done()


@pytest.mark.parametrize("wrong_account", [True, False])
async def test_reauth_via_flow_manager_preserves_original_account(
    hass, api, oauth, wrong_account
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            "account_id": "original",
            "vessels": [{"vesselId": "old-spa"}],
            "auth_implementation": DOMAIN,
            "token": {"access_token": "old"},
        },
    )
    entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": "reauth", "entry_id": entry.entry_id},
        data=entry.data,
    )
    assert result["step_id"] == "reauth_confirm"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    api.async_get_user_info.return_value = {
        "account": {"accountId": "different" if wrong_account else "original"}
    }
    with patch.object(hass.config_entries, "async_schedule_reload") as reload:
        result = await finish_login(hass, result)
        assert result["reason"] == (
            "wrong_account" if wrong_account else "reauth_successful"
        )
        if wrong_account:
            reload.assert_not_called()
            assert entry.data["token"]["access_token"] == "old"
        else:
            reload.assert_called_once_with(entry.entry_id)
            assert entry.data["token"]["access_token"] == "access"
    assert entry.data["vessels"] == [{"vesselId": "old-spa"}]
    api.async_get_vessels.assert_not_awaited()
