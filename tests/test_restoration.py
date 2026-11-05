"""End-to-end model/entity regressions for the community restoration."""

import asyncio
from concurrent.futures import Future
from types import SimpleNamespace
import threading
from unittest.mock import AsyncMock, Mock, patch

import pytest
from aiohttp import ClientResponseError
from homeassistant.components.climate import HVACAction
from homeassistant.components.light import ColorMode
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.gecko.api import OAuthGeckoApi
from custom_components.gecko.climate import GeckoClimate
from custom_components.gecko.coordinator import GeckoVesselCoordinator
from custom_components.gecko.fan import GeckoFan
from custom_components.gecko.light import GeckoLight
from custom_components.gecko.sensor import GeckoTemperatureStatusSensor, GeckoFlowSpeedModeSensor
from custom_components.gecko.binary_sensor import GeckoEcoModeBinarySensor, GeckoTemperatureHeatingBinarySensor
from custom_components.gecko.gecko_iot_client.models.zone_parser import ZoneConfigurationParser
from custom_components.gecko.gecko_iot_client.models.zone_types import ZoneType
from custom_components.gecko.gecko_iot_client.models.operation_mode_controller import OperationModeController
from custom_components.gecko.gecko_iot_client.models.operation_mode import OperationMode
from custom_components.gecko.gecko_iot_client.models.flow_zone import FlowZoneInitiator
from custom_components.gecko.gecko_iot_client.transporters.mqtt.client import MqttClient
from custom_components.gecko.gecko_iot_client.helpers import telemetry


@pytest.fixture
def controls(hass):
    entry = MockConfigEntry(domain="gecko", entry_id="restoration", data={})
    entry.add_to_hass(hass)
    coordinator = GeckoVesselCoordinator(hass, entry.entry_id, "vessel", "monitor", "Spa")
    entry.runtime_data = SimpleNamespace(coordinators=[coordinator], api_client=None)
    published = []
    # Pure model fixtures still represent an available connection for actions.
    from custom_components.gecko.connection_manager import GECKO_CONNECTION_MANAGER_KEY
    connection = SimpleNamespace(is_fully_connected=True, gecko_client=None)
    hass.data[GECKO_CONNECTION_MANAGER_KEY] = Mock(get_connection=Mock(return_value=connection))

    def build(config, state):
        parser = ZoneConfigurationParser()
        zones = parser.parse_zones_configuration(config)
        parser.apply_state_to_zones(zones, {"state": {"reported": {"zones": state}}})
        for values in zones.values():
            for zone in values:
                zone.set_publish_callback(lambda typ, identifier, data: published.append((typ, identifier, data)))
        coordinator._zones = zones
        return coordinator, entry, zones, published
    return build


@pytest.mark.parametrize("minimum,maximum,step,requested_percentage,expected", [
    (50,100,50,50,50), (50,100,50,100,100), (33,99,33,100,99),
    (0,100,1,35,35), (100,100,0,100,100),
])
async def test_pump_commands_use_parser_preserved_configuration(hass, controls, minimum, maximum, step, requested_percentage, expected):
    config={"flow":{"1":{"speed":{"minimum":minimum,"maximum":maximum,"stepIncrement":step}}}}
    coord, entry, zones, published = controls(config, {"flow":{"1":{"active":True,"speed":maximum}}})
    zone=zones[ZoneType.FLOW_ZONE][0]
    assert zone.speed_config == config['flow']['1']['speed']
    fan=GeckoFan(coord,entry,zone);fan.hass=hass
    await fan.async_set_percentage(requested_percentage)
    assert published[-1][2] == {"speed":expected,"active":True}


async def test_full_speed_alone_does_not_imply_two_speed_pump(controls):
    coord,entry,zones,_=controls({"flow":{"1":{}}},{"flow":{"1":{"active":True,"speed":100}}})
    zone=zones[ZoneType.FLOW_ZONE][0]
    assert not telemetry.reports_binary_near_max_speed_encoding(zone)
    fan=GeckoFan(coord,entry,zone)
    assert fan.speed_count == 1


async def test_binary_low_readback_is_remembered_for_high(controls):
    coord,entry,zones,_=controls({"flow":{"1":{"speed":{"minimum":50,"maximum":100,"stepIncrement":50}}}}, {"flow":{"1":{"active":True,"speed":99}}})
    zone=zones[ZoneType.FLOW_ZONE][0]
    assert telemetry.derive_flow_speed_mode(zone) == "low"
    zone.speed=100
    assert telemetry.derive_flow_speed_mode(zone) == "high"
    assert telemetry.get_flow_speed_value_for_mode(zone,"high") == 100


async def test_pump_on_state_is_physical_and_initiators_clear(controls):
    coord,entry,zones,_=controls({"flow":{"1":{}}},{"flow":{"1":{"active":True,"speed":50,"initiators_":["FI"]}}})
    zone=zones[ZoneType.FLOW_ZONE][0];fan=GeckoFan(coord,entry,zone)
    assert fan.is_on is True
    assert fan.extra_state_attributes['manual_demand'] is False
    assert fan.extra_state_attributes['filtration_active'] is True
    zone.initiators_=None;fan._update_from_zone()
    assert fan.extra_state_attributes['initiators'] is None


async def test_automatic_pump_demand_cannot_be_stopped(hass,controls):
    coord,entry,zones,published=controls({"flow":{"1":{}}},{"flow":{"1":{"active":True,"initiators_":["FI","UD"]}}})
    fan=GeckoFan(coord,entry,zones[ZoneType.FLOW_ZONE][0]);fan.hass=hass
    with pytest.raises(HomeAssistantError) as caught:
        await fan.async_turn_off()
    assert published == []


@pytest.mark.parametrize('status,action',[(0,HVACAction.IDLE),(1,HVACAction.HEATING),(2,HVACAction.IDLE),(3,HVACAction.IDLE),(4,HVACAction.HEATING),(5,HVACAction.HEATING),(6,HVACAction.COOLING),(7,HVACAction.DEFROSTING),(8,HVACAction.IDLE)])
async def test_climate_combines_eco_heat_source_and_fault(controls,status,action):
    coord,_,zones,_=controls({"temperatureControl":{"1":{}}},{"temperatureControl":{"1":{"status_":status,"mode_":{"eco":True}}}})
    climate=GeckoClimate(coord,zones[ZoneType.TEMPERATURE_CONTROL_ZONE][0])
    assert climate.hvac_action == action
    assert climate.extra_state_attributes['eco_mode'] is True
    assert climate.extra_state_attributes['heat_pump_error'] is (status==8)
    assert 'heat_source' in climate.extra_state_attributes


@pytest.mark.parametrize('entity_class,zone_type,initial,new,expected',[
    (GeckoTemperatureStatusSensor,ZoneType.TEMPERATURE_CONTROL_ZONE,{"status_":0},{"status_":1},'HEATING'),
    (GeckoFlowSpeedModeSensor,ZoneType.FLOW_ZONE,{"active":False},{"active":True,"speed":50},'medium'),
    (GeckoEcoModeBinarySensor,ZoneType.TEMPERATURE_CONTROL_ZONE,{"mode_":{"eco":False}},{"mode_":{"eco":True}},True),
    (GeckoTemperatureHeatingBinarySensor,ZoneType.TEMPERATURE_CONTROL_ZONE,{"status_":0},{"status_":1},True),
])
async def test_new_zone_entities_rebind_after_reconnect(controls,entity_class,zone_type,initial,new,expected):
    config={zone_type.value:{"1":{}}}
    coord,_,zones,_=controls(config,{zone_type.value:{"1":initial}})
    entity=entity_class(coord,zones[zone_type][0])
    controls(config,{zone_type.value:{"1":new}})
    with patch.object(entity,'async_write_ha_state'):
        entity._handle_coordinator_update()
    actual=entity.is_on if hasattr(entity,'is_on') else entity.native_value
    assert actual == expected


async def test_external_return_to_previous_color_wins(hass,controls):
    coord,entry,zones,published=controls({"lighting":{"1":{}}},{"lighting":{"1":{"active":True,"rgbi":[255,0,0,1]}}})
    zone=zones[ZoneType.LIGHTING_ZONE][0];light=GeckoLight(coord,entry,zone);light.hass=hass
    await light.async_turn_on(rgb_color=(0,0,255))
    zone.update_from_state({'rgbi':[0,0,255,1]});light._update_state()
    zone.update_from_state({'rgbi':[255,0,0,1]});light._update_state()
    assert light.rgb_color == (255,0,0)
    assert published[-1][2]['rgbi'] == [0,0,255,1]


async def test_plain_light_stays_onoff_and_later_color_is_discovered(controls):
    coord,entry,zones,_=controls({"lighting":{"1":{}}},{"lighting":{"1":{"active":True}}})
    zone=zones[ZoneType.LIGHTING_ZONE][0];light=GeckoLight(coord,entry,zone)
    assert light.supported_color_modes == {ColorMode.ONOFF}
    zone.update_from_state({'rgbi':[20,0,10,1]});light._update_state()
    assert light.supported_color_modes == {ColorMode.RGB}


async def test_brightness_preserves_hue_and_effect_plus_color(hass,controls):
    coord,entry,zones,published=controls({"lighting":{"1":{}}},{"lighting":{"1":{"active":True,"rgbi":[255,0,128,1]}}})
    light=GeckoLight(coord,entry,zones[ZoneType.LIGHTING_ZONE][0]);light.hass=hass
    for level in (40,100,255):
        await light.async_turn_on(brightness=level)
        light._update_state()
    assert light.rgb_color == (255,0,128)
    await light.async_turn_on(effect='rainbow',rgb_color=(0,255,0),brightness=255)
    assert published[-2][2] == {'effect':'rainbow','active':True}
    assert published[-1][2]['rgbi'] == [0,255,0,1]


async def test_failed_light_publish_preserves_reported_color_and_cache(hass,controls):
    coord,entry,zones,_=controls({"lighting":{"1":{}}},{"lighting":{"1":{"active":True,"rgbi":[255,0,0,1]}}})
    zone=zones[ZoneType.LIGHTING_ZONE][0];light=GeckoLight(coord,entry,zone);light.hass=hass
    zone.set_publish_callback(Mock(side_effect=ConnectionError('publish failed')))
    with pytest.raises(HomeAssistantError) as caught:
        await light.async_turn_on(rgb_color=(0,0,255))
    assert caught.value.translation_key == "command_failed"
    light._update_state()
    assert light.rgb_color == (255,0,0)


@pytest.mark.parametrize('name',['Super Savings','super savings','SUPER_SAVINGS','SuperSavings'])
def test_watercare_display_names_publish_same_mode(name):
    controller=OperationModeController();callback=Mock();controller.set_publish_callback(callback)
    controller.set_mode_by_name(name)
    callback.assert_called_once_with('operationMode',{'operationMode':OperationMode.SUPER_SAVINGS.value})


async def test_missing_refresh_token_triggers_reauth():
    api=OAuthGeckoApi.__new__(OAuthGeckoApi)
    api._oauth_session=SimpleNamespace(token={'access_token':'access'},async_ensure_token_valid=AsyncMock())
    with pytest.raises(ConfigEntryAuthFailed,match='refresh token'):
        await api.async_get_access_token()
    api._oauth_session.async_ensure_token_valid.assert_not_awaited()


async def test_refresh_requests_coalesce_and_success_is_briefly_reused(hass):
    entry=MockConfigEntry(domain='gecko',entry_id='tokens',data={});entry.add_to_hass(hass)
    gate=asyncio.Event()
    async def refresh(_):
        await gate.wait()
        return {'brokerUrl':'wss://fresh'}
    api=SimpleNamespace(async_get_monitor_livestream=AsyncMock(side_effect=refresh))
    entry.runtime_data=SimpleNamespace(api_client=api)
    coord=GeckoVesselCoordinator(hass,entry.entry_id,'v','m','Spa')
    tasks=[asyncio.create_task(coord._async_get_fresh_broker_url()) for _ in range(8)]
    await asyncio.sleep(0);gate.set()
    assert await asyncio.gather(*tasks) == ['wss://fresh']*8
    assert await coord._async_get_fresh_broker_url() == 'wss://fresh'
    api.async_get_monitor_livestream.assert_awaited_once()


async def test_rate_limit_honors_retry_after_and_returns_no_stale_url(hass):
    entry=MockConfigEntry(domain='gecko',entry_id='limited',data={});entry.add_to_hass(hass)
    error=ClientResponseError(request_info=SimpleNamespace(real_url='https://example.invalid'),history=(),status=429,headers={'Retry-After':'180'})
    api=SimpleNamespace(async_get_monitor_livestream=AsyncMock(side_effect=error));entry.runtime_data=SimpleNamespace(api_client=api)
    coord=GeckoVesselCoordinator(hass,entry.entry_id,'v','m','Spa');before=hass.loop.time()
    assert await coord._async_get_fresh_broker_url() is None
    assert coord._token_backoff_until >= before+180
    assert await coord._async_get_fresh_broker_url() is None
    api.async_get_monitor_livestream.assert_awaited_once()


def test_mqtt_builder_uses_actual_keepalive_keyword():
    from custom_components.gecko.gecko_iot_client.transporters.mqtt import client as client_module
    mqtt=MqttClient()
    mqtt._parse_websocket_url=Mock(return_value=('example.invalid',{'authorizer':'auth','token':'token','signature':'sig'}))
    mqtt._wait_for_connection=Mock(return_value=True)
    with patch.object(client_module.mqtt5_client_builder,'direct_with_custom_authorizer') as builder:
        mqtt.connect('wss://example.invalid','test')
    kwargs=builder.call_args.kwargs
    assert kwargs['keep_alive_interval_sec'] == 60
    assert kwargs['ping_timeout_ms'] == 10000
    assert 'keep_alive_secs' not in kwargs


def test_native_client_is_stopped_even_after_transport_drop():
    mqtt=MqttClient();native=Mock();mqtt._client=native;mqtt._connected=False
    mqtt.disconnect()
    native.stop.assert_called_once()
    assert mqtt._client is None


async def test_two_speed_start_waits_for_report_before_high(hass, controls):
    coord,entry,zones,published=controls({'flow':{'1':{'speed':{'minimum':50,'maximum':100,'stepIncrement':50}}}}, {'flow':{'1':{'active':False,'speed':100}}})
    zone=zones[ZoneType.FLOW_ZONE][0]
    fan=GeckoFan(coord,entry,zone);fan.hass=hass
    task=asyncio.create_task(fan.async_set_percentage(100))
    await hass.async_block_till_done()
    assert published[-1][2]['speed'] == 50
    assert not task.done()
    # Optimistic local state from publishing must not confirm startup.
    coord.async_update_listeners()
    await asyncio.sleep(0)
    assert not task.done()
    zone.update_from_state({'active':True,'speed':50})
    coord.async_update_listeners()
    await task
    assert [message[2]['speed'] for message in published] == [50,100]
