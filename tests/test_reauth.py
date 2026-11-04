"""Reauthentication must retain the account's vessels and reject another account."""
from unittest.mock import AsyncMock, Mock, patch
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from custom_components.gecko.config_flow import ConfigFlow


@pytest.mark.parametrize('account,expected',[('original','update'),('different','wrong_account')])
async def test_reauth_account_identity_and_existing_data(hass,account,expected):
    entry=MockConfigEntry(domain='gecko',data={'account_id':'original','vessels':[{'vesselId':'spa'}],'user_id':'user','token':{'access_token':'old'}})
    entry.add_to_hass(hass)
    flow=ConfigFlow();flow.hass=hass;flow.context={'source':'reauth','entry_id':entry.entry_id}
    token={'token':{'access_token':'new','refresh_token':'refresh'}}
    with patch.object(flow,'_get_reauth_entry',return_value=entry), patch.object(flow,'_resolve_user_and_account',AsyncMock(return_value=('user',{},account))), patch.object(flow,'async_update_reload_and_abort',Mock(return_value={'type':'abort','reason':'updated'})) as update, patch('custom_components.gecko.api.ConfigFlowGeckoApi'):
        result=await flow.async_oauth_create_entry(token)
    if expected == 'update':
        assert update.call_args.kwargs['data'] == {**entry.data,**token}
        assert result['reason'] == 'updated'
    else:
        assert result['reason'] == 'wrong_account'
        update.assert_not_called()
        assert entry.data['token']['access_token'] == 'old'
