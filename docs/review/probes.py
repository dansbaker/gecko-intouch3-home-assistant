"""Offline review probes; invoke with PR number and its extracted checkout."""
import asyncio
import sys
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock
sys.path.insert(0, sys.argv[2])
pr=int(sys.argv[1])

def report(name, actual, expected):
 print(f'{name}: actual={actual!r}; expected={expected!r}; '+('PASS' if actual==expected else 'DEFECT REPRODUCED'))

if pr==32:
 from custom_components.gecko.fan import GeckoFan
 from gecko_iot_client.models.flow_zone import FlowZone
 z=FlowZone('1', {'name':'Pump'});z.active=True;z.speed=50;z.initiators_=['UD']
 f=GeckoFan.__new__(GeckoFan);f._zone=z;f._update_from_zone()
 z.initiators_=None;f._update_from_zone()
 report('cleared initiators',f._attr_extra_state_attributes.get('initiators'),None)
elif pr==33:
 from homeassistant.helpers.config_entry_oauth2_flow import LocalOAuth2ImplementationWithPkce
 async def check():
  obj=LocalOAuth2ImplementationWithPkce(NS(),'gecko','public','https://example.com/auth','https://example.com/token')
  obj._token_request=AsyncMock(return_value={'access_token':'new','expires_in':3600})
  result=await obj.async_refresh_token({'access_token':'old','refresh_token':'existing','expires_in':3600})
  report('HA core already preserves omitted refresh token',result['refresh_token'],'existing')
 asyncio.run(check())
elif pr==37:
 from gecko_iot_client.models.zone_parser import ZoneConfigurationParser
 from gecko_iot_client.models.zone_types import ZoneType
 from custom_components.gecko.telemetry import get_supported_flow_speed_modes,get_flow_speed_value_for_mode
 from custom_components.gecko.sensor import GeckoTemperatureStatusSensor
 from gecko_iot_client.models.temperature_control_zone import TemperatureControlZone,TemperatureControlZoneStatus as S
 p=ZoneConfigurationParser();zs=p.parse_zones_configuration({'flow':{'1':{'name':'Pump','speed':{'minimum':50,'maximum':100,'stepIncrement':50}}}})
 z=zs[ZoneType.FLOW_ZONE][0];z.active=True;z.speed=50
 report('real parser retains speed ladder',z.speed_config,{'minimum':50,'maximum':100,'stepIncrement':50})
 report('high command with range and current low speed',get_flow_speed_value_for_mode(z,'high'),100)
 z.speed=100
 report('command changes with current speed',get_flow_speed_value_for_mode(z,'high'),100)
 old=TemperatureControlZone('1',{});old.status_=S.IDLE
 new=TemperatureControlZone('1',{});new.status_=S.HEATING
 sensor=GeckoTemperatureStatusSensor.__new__(GeckoTemperatureStatusSensor);sensor._zone=old
 sensor.coordinator=NS(get_zones_by_type=lambda _: [new]);sensor._update_from_zone()
 report('new telemetry sensor after zone replacement',sensor._attr_native_value,'HEATING')
elif pr==54:
 from homeassistant.helpers.config_entry_oauth2_flow import async_get_redirect_uri
 report('redirect with my loaded',async_get_redirect_uri(NS(config=NS(components={'my'}))),'https://my.home-assistant.io/redirect/oauth')
elif pr==56:
 from custom_components.gecko.climate import GeckoClimate
 from gecko_iot_client.models.temperature_control_zone import TemperatureControlZone
 z=TemperatureControlZone('1',{});f=GeckoClimate.__new__(GeckoClimate);f._zone=z
 for value in [None,True,False]:
  z.mode_=NS(eco=value) if value is not None else None;f._update_from_zone()
  report('eco '+str(value),f._attr_extra_state_attributes['eco_mode'],value)
elif pr==57:
 from custom_components.gecko.light import GeckoLight
 from gecko_iot_client.models.lighting_zone import RGB
 z=NS(active=True,rgbi=RGB(r=255,g=0,b=0,i=1),effect=None)
 f=GeckoLight.__new__(GeckoLight);f._attr_name='Light';f._get_zone_state=lambda:z
 f._cached_base_rgb=None;f._cached_brightness=None;f._previous_base_rgb=None;f._previous_brightness=None;f._known_effects=set()
 f._update_state()
 # Simulate a completed HA change from red to blue, followed by app returning to red.
 f._previous_base_rgb=f._cached_base_rgb;f._previous_brightness=f._cached_brightness
 f._cached_base_rgb=(0,0,255);f._cached_brightness=255
 z.rgbi=RGB(r=0,g=0,b=255,i=1);f._update_state()
 z.rgbi=RGB(r=255,g=0,b=0,i=1);f._update_state()
 report('external return to previous confirmed color',f._attr_rgb_color,(255,0,0))
 # Every LightingZone has rgbi/effect fields, even where no support was reported.
 from gecko_iot_client.models.lighting_zone import LightingZone
 f._zone=LightingZone('1',{})
 print('MODEL OBSERVATION: empty LightingZone advertises color via hasattr:',f._zone_supports_color(),'; hardware capability remains unproven')
elif pr==60:
 from custom_components.gecko.climate import GeckoClimate,_HVAC_ACTION_BY_STATUS
 from gecko_iot_client.models.temperature_control_zone import TemperatureControlZone,TemperatureControlZoneStatus as S
 from homeassistant.components.climate import HVACAction as A
 expected=[A.IDLE,A.HEATING,A.COOLING,A.IDLE,A.HEATING,A.HEATING,A.COOLING,A.DEFROSTING,A.IDLE]
 report('all 9 HVAC status mappings',[_HVAC_ACTION_BY_STATUS[s] for s in S],expected)
 z=TemperatureControlZone('1',{});z.status_=S.HEAT_PUMP_ERROR
 f=GeckoClimate.__new__(GeckoClimate);f._zone=z;f._update_from_zone()
 report('heat pump fault exposed',f._attr_extra_state_attributes['heat_pump_error'],True)

elif pr==65:
 from awsiot import mqtt5_client_builder as builder
 from unittest.mock import patch
 for kwargs in [{'keep_alive_secs':30},{'keep_alive_interval_sec':60,'ping_timeout_ms':10000}]:
  with patch('awscrt.mqtt5.Client',side_effect=lambda client_options:NS(options=client_options)):
   client=builder.direct_with_custom_authorizer(endpoint='example.invalid',auth_authorizer_name='example',auth_username='',auth_password=b'',auth_token_key_name='token',auth_token_value='example',auth_authorizer_signature='example',client_id='review',**kwargs)
   print(kwargs,'=> keepalive',client.options.connect_options.keep_alive_interval_sec,'ping timeout',client.options.ping_timeout_ms)
