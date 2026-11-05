"""Waterlab regressions using the public fork's documented v6 payload shape."""
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from aiohttp import ClientResponseError
from pytest_homeassistant_custom_component.common import MockConfigEntry
from custom_components.gecko.coordinator import GeckoVesselCoordinator
from custom_components.gecko.sensor import GeckoWaterlabSensor
from custom_components.gecko.gecko_iot_client.helpers.waterlab import extract_readings
from custom_components.gecko.gecko_iot_client.helpers.shadow_metrics import extract_extension_metrics, water_quality_kind


def test_v6_chemistry_records_preserve_source_and_units():
    result = extract_readings({'status': {'readings': {
        'ph': {'value':7.85,'unit':'ph','source':'monitor','status':'high'},
        'orp': {'value':198,'unit':'mV','source':'monitor'},
        'alkalinity': {'value':100,'unit':'ppm','source':'manual'},
        'waterTemp': {'value':29,'unit':'°C'},
        'calibration': {'value':999},
    }}})
    assert result['ph']['value'] == 7.85
    assert result['orp']['unit'] == 'mV'
    assert result['alkalinity']['source'] == 'manual'
    assert set(result) == {'ph','orp','alkalinity','waterTemp'}


@pytest.mark.parametrize('value', [None,True,'7.4',float('nan'),float('inf'),-1,15])
def test_invalid_ph_is_not_a_reading(value):
    assert extract_readings({'readings':{'ph':{'value':value}}}) == {}


def test_cloud_summary_is_supported_but_calibration_never_is():
    assert extract_readings({'status':{'discElements':{'phStatus':{'value':7.2},'orpStatus':{'mv':650}}}})['orp']['value'] == 650
    assert extract_readings({'status':{'calibration':{'ph':7.0,'orp':650}}}) == {}
    assert water_quality_kind('zones.waterlab.1.ph.calibration.value') is None
    assert water_quality_kind('zones.waterlab.1.ph.value') == 'ph'
    assert water_quality_kind('zones.waterlab.1.orp.reading') == 'orp'


def test_extensions_are_reported_only_bounded_and_finite():
    state={'state':{'desired':{'zones':{'waterlab':{'ph':9}}},'reported':{'zones':{'waterlab':{'ph':{'value':7.4},'token':123,'bad':float('nan')},'flow':{'1':{'speed':50}}}}}}
    assert extract_extension_metrics(state) == {'zones.waterlab.ph.value':7.4}


@pytest.fixture
def cloud(hass):
    entry=MockConfigEntry(domain='gecko',data={'account_id':'account'})
    entry.add_to_hass(hass)
    coordinator=GeckoVesselCoordinator(hass,entry.entry_id,'vessel','monitor','Spa')
    api=SimpleNamespace(async_get_vessel_detail=AsyncMock(return_value={'status':{'readings':{'ph':{'value':7.4,'source':'monitor'}}}}))
    entry.runtime_data=SimpleNamespace(coordinators=[coordinator],api_client=api)
    return coordinator,api


async def test_polling_is_coalesced_by_interval_and_discovers_entities(cloud):
    coordinator,api=cloud
    discovered=[]
    coordinator.register_zone_update_callback(lambda:discovered.append(set(coordinator.waterlab_readings)))
    await coordinator._async_update_waterlab()
    await coordinator._async_update_waterlab()
    api.async_get_vessel_detail.assert_awaited_once_with('account','vessel')
    assert discovered == [{'ph'}]
    sensor=GeckoWaterlabSensor(coordinator,'ph')
    # Cloud chemistry stays available even when the MQTT spa link is down.
    assert sensor.available
    assert sensor.native_value == 7.4
    assert sensor.extra_state_attributes['source'] == 'monitor'
    assert sensor.extra_state_attributes['last_successful_poll']


async def test_failed_poll_makes_cached_reading_unavailable_then_recovers(cloud):
    coordinator,api=cloud
    await coordinator._async_update_waterlab()
    sensor=GeckoWaterlabSensor(coordinator,'ph')
    api.async_get_vessel_detail.side_effect=TimeoutError
    coordinator._waterlab_next_poll=0
    await coordinator._async_update_waterlab()
    assert not sensor.available
    assert sensor.native_value == 7.4
    api.async_get_vessel_detail.side_effect=None
    api.async_get_vessel_detail.return_value={'readings':{}}
    coordinator._waterlab_next_poll=0
    await coordinator._async_update_waterlab()
    assert not sensor.available # Removed readings must never linger as current.


@pytest.mark.parametrize('status',[403,404,429])
async def test_optional_endpoint_failure_does_not_raise_or_disconnect_spa(cloud,status):
    coordinator,api=cloud
    api.async_get_vessel_detail.side_effect=ClientResponseError(None,(),status=status,headers={'Retry-After':'900'})
    await coordinator._async_update_waterlab()
    assert not coordinator.waterlab_available
    assert coordinator._waterlab_poll_disabled == (status in (403,404))
    await coordinator._async_update_waterlab()
    assert api.async_get_vessel_detail.await_count == 1


async def test_poll_timer_is_independent_of_mqtt_and_registered_for_unload(hass,cloud):
    import asyncio
    from unittest.mock import Mock, patch
    coordinator,api=cloud
    tasks=[]
    def spawn(_hass, coroutine, name):
        task=asyncio.create_task(coroutine)
        tasks.append(task)
        return task
    entry=SimpleNamespace(async_on_unload=Mock(),async_create_background_task=spawn)
    cancel=Mock()
    with patch('homeassistant.helpers.event.async_track_time_interval',return_value=cancel) as timer:
        coordinator.async_start_waterlab_polling(entry)
        await tasks[-1]
        assert timer.call_args.args[2].total_seconds() == 300
        entry.async_on_unload.assert_called_once_with(cancel)
        # MQTT updates do not change the separately registered timer.
        coordinator.async_set_updated_data({'mqtt':'busy'})
        coordinator._waterlab_next_poll=0
        timer.call_args.args[1](None)
        await tasks[-1]
        assert api.async_get_vessel_detail.await_count == 2
