#!/usr/bin/env python3
"""
Gecko Hot Tub Controller

A comprehensive Python class for controlling Gecko hot tub/spa systems via AWS IoT Device Shadow.
Now handles authentication tokens internally and automatically refreshes them.

Usage:
    from gecko_controller import GeckoHotTubController
    
    # Initialize with tokens instead of WSS URL
    controller = GeckoHotTubController(
        access_token="your_access_token",
        refresh_token="your_refresh_token", 
        monitor_id="your_monitor_id"  # Must be obtained from API
    )
    
    # Use context manager for automatic cleanup
    with controller:
        controller.set_temperature(40)
        controller.turn_on_lights()
        controller.start_pump(1, speed=75)
        
        temp = controller.get_temperature()
        status = controller.get_system_status()
"""

import json
import time
import base64
import requests
import logging
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from awsiot import mqtt5_client_builder
from awscrt import mqtt5

_LOGGER = logging.getLogger(__name__)

class HeatingMode(Enum):
    """Temperature control heating modes"""
    STANDARD = 0
    ECO = 1

class FlowZoneStatus(Enum):
    """Flow zone status indicators"""
    INACTIVE = 0
    ACTIVE = 1

@dataclass
class TemperatureStatus:
    """Current temperature control status"""
    current_temp: int
    set_point: int
    heating_status: int
    eco_mode: bool
    flow_status: str

@dataclass
class FlowZoneInfo:
    """Information about a flow/pump zone"""
    zone_id: int
    active: bool
    speed: int
    initiators: List[str]

@dataclass
class ConnectivityStatus:
    """System connectivity information"""
    gateway_status: str
    vessel_status: str
    rf_channel: int
    rf_strength: int

@dataclass
class SystemStatus:
    """Complete hot tub system status"""
    connectivity: ConnectivityStatus
    temperature: TemperatureStatus
    flow_zones: List[FlowZoneInfo]
    lighting_zones: Dict[int, bool]
    operation_mode: int

@dataclass
class GeckoTokens:
    """Authentication token container"""
    access_token: str
    refresh_token: str
    expires_at: Optional[datetime] = None
    monitor_id: Optional[str] = None

class GeckoTokenManager:
    """Manages Gecko authentication tokens and automatic refresh"""
    
    def __init__(self, access_token: str, refresh_token: str, monitor_id: str = None):
        self.access_token = access_token
        self.refresh_token = refresh_token  
        self.monitor_id = monitor_id
        self.expires_at = None
        
        # Auth0 configuration
        self.auth0_domain = "gecko-prod.us.auth0.com"
        self.client_id = "IlbhNGMeYfb8ovs0gK43CjPybltA3ogH"
        self.audience = "https://api.geckowatermonitor.com"
        
        # Extract monitor ID from token if not provided
        if not self.monitor_id:
            self.monitor_id = self._extract_monitor_id_from_token(access_token)
    
    def _extract_monitor_id_from_token(self, token: str) -> Optional[str]:
        """Extract monitor ID from JWT token"""
        try:
            # JWT tokens have 3 parts separated by dots
            payload = token.split('.')[1]
            # Add padding if needed
            payload += '=' * (4 - len(payload) % 4)
            decoded = base64.b64decode(payload)
            token_data = json.loads(decoded)
            return str(token_data.get('sub', '').split('|')[-1])  # Extract user ID
        except Exception as e:
            _LOGGER.warning(f"⚠️  Could not extract monitor ID from token: {e}")
            return None
    
    def is_token_expired(self) -> bool:
        """Check if access token is expired or close to expiring"""
        if not self.expires_at:
            # Assume expired if no expiry info
            return True
        
        # Consider expired if less than 5 minutes remaining
        buffer = timedelta(minutes=5)
        return datetime.now() + buffer >= self.expires_at

    def are_aws_credentials_expired(self, buffer: timedelta = timedelta(minutes=5)) -> bool:
        """Check if AWS credentials are expired (with buffer)"""
        if not self.aws_creds_expires_at:
            return True  # No expiry time means we should refresh
        
        return datetime.now() + buffer >= self.aws_creds_expires_at

    def refresh_access_token(self) -> bool:
        """Refresh the access token using refresh token"""
        try:
            _LOGGER.info("🔄 Refreshing access token...")
            
            token_url = f"https://{self.auth0_domain}/oauth/token"
            
            data = {
                'grant_type': 'refresh_token',
                'client_id': self.client_id,
                'refresh_token': self.refresh_token
            }
            
            response = requests.post(token_url, data=data)
            
            if response.status_code != 200:
                _LOGGER.error(f"❌ Token refresh failed: {response.status_code} - {response.text}")
                return False
            
            tokens = response.json()
            
            self.access_token = tokens['access_token']
            if 'refresh_token' in tokens:
                self.refresh_token = tokens['refresh_token']
            
            # Set expiry time (default 1 hour if not specified)
            expires_in = tokens.get('expires_in', 3600)
            self.expires_at = datetime.now() + timedelta(seconds=expires_in)
            
            _LOGGER.info("✅ Access token refreshed successfully")
            return True
            
        except Exception as e:
            _LOGGER.error(f"❌ Token refresh error: {e}")
            return False
    
    def get_aws_credentials(self) -> Dict[str, str]:
        """Get AWS IoT credentials using current access token"""
        stream_url = f"https://api.geckowatermonitor.com/v2/monitors/{self.monitor_id}/liveStream"
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(stream_url, headers=headers)
        
        # If unauthorized, try refreshing the OAuth token once
        if response.status_code == 401 or response.status_code == 403:
            _LOGGER.info("🔄 OAuth token may be expired, attempting refresh...")
            if self.refresh_access_token():
                # Retry with new OAuth token
                headers['Authorization'] = f'Bearer {self.access_token}'
                response = requests.get(stream_url, headers=headers)
                
                if response.status_code != 200:
                    raise Exception(f"Failed to get AWS credentials even after token refresh: {response.status_code} - {response.text}")
            else:
                # OAuth refresh failed - the refresh token itself has expired
                # This requires user to re-authenticate
                raise Exception(f"OAuth refresh token has expired. User needs to re-authenticate. Error: {response.status_code} - {response.text}")
        elif response.status_code != 200:
            raise Exception(f"Failed to get AWS credentials: {response.status_code} - {response.text}")
        
        return response.json()
    
    def get_valid_access_token(self) -> str:
        """Get a valid access token, refreshing if needed"""
        if self.is_token_expired():
            if not self.refresh_access_token():
                raise Exception("Failed to refresh expired token")
        return self.access_token

class GeckoHotTubController:
    """
    Comprehensive controller for Gecko hot tub systems via AWS IoT.
    
    Provides high-level methods to control temperature, lighting, pumps,
    and monitor system status through AWS IoT Device Shadow service.
    """
    
    def __init__(self, access_token: str = None, refresh_token: str = None, 
                 monitor_id: str = None, broker_url: str = None):
        """
        Initialize the hot tub controller with authentication tokens.
        
        Args:
            access_token: OAuth2 access token for API calls
            refresh_token: OAuth2 refresh token for token renewal  
            monitor_id: Hot tub monitor/device ID (required, must be obtained from API)
            broker_url: Deprecated - use tokens instead
        """
        # Handle legacy broker_url usage
        if broker_url and not access_token:
            _LOGGER.warning("⚠️  Warning: broker_url parameter is deprecated. Use tokens instead.")
            self._init_from_broker_url(broker_url)
            return
        
        # Token-based initialization (preferred)
        if not access_token or not refresh_token:
            raise ValueError("access_token and refresh_token are required")
        
        # Monitor ID is required and must be provided or obtained from API
        if not monitor_id:
            raise ValueError("monitor_id is required. It must be obtained from the Gecko API (/v3/accounts/{accountId}/vessels)")
        
        self.monitor_id = monitor_id
        
        # Initialize token manager
        self.token_manager = GeckoTokenManager(access_token, refresh_token, self.monitor_id)
        
        # Generate unique client ID
        import random
        random_hex = ''.join(random.choices('0123456789abcdef', k=8))
        self.client_id = f"gecko-controller-{random_hex}"
        
        # Connection state
        self.mqtt5_client = None
        self.connected = False
        self.last_shadow_state = {}
        self.shadow_callbacks = []
        
        # AWS credentials (will be fetched when needed)
        self.aws_creds = None
        self.aws_creds_expires_at = None
        self.broker_url = None
        
        _LOGGER.info(f"🏊‍♀️ Gecko Hot Tub Controller initialized")
        _LOGGER.info(f"   Monitor ID: {self.monitor_id}")
        _LOGGER.info(f"   Client ID: {self.client_id}")
        _LOGGER.info(f"   Token-based authentication: ✅")
        
    def _init_from_broker_url(self, broker_url: str):
        """Legacy initialization from broker URL (deprecated)"""
        self.broker_url = broker_url
        self.device_id = None
        self._parse_broker_url()
        
        # Generate unique client ID
        import random
        random_hex = ''.join(random.choices('0123456789abcdef', k=8))
        self.client_id = f"gecko-controller-{random_hex}"
        
        # Connection state
        self.mqtt5_client = None
        self.connected = False
        self.last_shadow_state = {}
        self.shadow_callbacks = []
        
        _LOGGER.info(f"🏊‍♀️ Gecko Hot Tub Controller initialized (legacy mode)")
        _LOGGER.info(f"   Monitor ID: {getattr(self, 'monitor_id', 'unknown')}")
        _LOGGER.info(f"   Client ID: {self.client_id}")

    def _ensure_aws_credentials(self):
        """Ensure we have valid AWS credentials"""
        _LOGGER.debug("🔍 _ensure_aws_credentials called")
        if hasattr(self, 'token_manager'):
            # Token-based approach
            _LOGGER.debug(f"   Token manager found: {type(self.token_manager)}")
            if not self.aws_creds or self.are_aws_credentials_expired():
                if self.aws_creds:
                    _LOGGER.info("🔄 AWS credentials expired, refreshing...")
                else:
                    _LOGGER.info("🔑 Fetching AWS IoT credentials...")
                try:
                    # Get new AWS credentials from token manager
                    self.aws_creds = self.token_manager.get_aws_credentials()
                    _LOGGER.debug(f"   AWS creds received: {list(self.aws_creds.keys()) if self.aws_creds else None}")
                    
                    # Parse and store AWS credentials expiry time
                    if 'expiresAt' in self.aws_creds:
                        try:
                            expires_at_str = self.aws_creds['expiresAt']
                            if expires_at_str.endswith('Z'):
                                expires_at_str = expires_at_str[:-1] + '+00:00'
                            self.aws_creds_expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                            _LOGGER.debug(f"   AWS credentials expire at: {self.aws_creds_expires_at}")
                        except Exception as e:
                            _LOGGER.warning(f"⚠️  Could not parse AWS credentials expiry time: {e}")
                            self.aws_creds_expires_at = datetime.now() + timedelta(hours=1)
                    else:
                        self.aws_creds_expires_at = datetime.now() + timedelta(hours=1)
                    
                    self.broker_url = self.aws_creds['brokerUrl']
                    _LOGGER.debug(f"   Broker URL: {self.broker_url[:50]}...")
                    self._parse_broker_url()
                    _LOGGER.info("✅ AWS credentials obtained")
                    _LOGGER.debug(f"   Monitor ID: {self.monitor_id}")
                    _LOGGER.debug(f"   Client ID: {self.client_id}")
                except Exception as e:
                    _LOGGER.error(f"❌ Failed to get AWS credentials: {e}", exc_info=True)
                    raise
            else:
                _LOGGER.debug("   Using cached AWS credentials")
        else:
            # Legacy broker URL approach
            _LOGGER.debug("   No token manager found, using legacy broker URL approach")
            if not self.broker_url:
                raise Exception("No broker URL or tokens provided")
            _LOGGER.debug(f"   Device ID: {getattr(self, 'device_id', 'unknown')}")
            _LOGGER.debug(f"   Client ID: {self.client_id}")

    def _parse_broker_url(self):
        """Parse the WSS broker URL to extract connection parameters"""
        if not self.broker_url:
            raise Exception("No broker URL available")
            
        parsed = urlparse(self.broker_url)
        
        self.host = parsed.hostname
        self.port = parsed.port or 443
        
        # Extract auth parameters from query string
        params = parse_qs(parsed.query)
        self.custom_auth_name = params.get('x-amz-customauthorizer-name', [None])[0]
        self.token = params.get('token', [None])[0]
        self.signature = params.get('x-amz-customauthorizer-signature', [None])[0]
        
        # Extract device ID from token if not provided (for legacy mode)
        if not hasattr(self, 'monitor_id') and self.token:
            try:
                decoded = base64.b64decode(self.token + '==')  # Add padding
                token_data = json.loads(decoded)
                self.monitor_id = str(token_data.get('monitorId', 'unknown'))
                # Legacy compatibility
                self.device_id = self.monitor_id
            except Exception as e:
                _LOGGER.warning(f"⚠️  Could not extract device ID from token: {e}")
                self.monitor_id = 'unknown'
                self.device_id = 'unknown'

    def _on_connection_success(self, callback_data):
        """Handle successful connection"""
        _LOGGER.info("✅ Connected to AWS IoT successfully!")
        _LOGGER.info(f"✅ Connection data: {callback_data}")
        self.connected = True

    def _on_connection_failure(self, callback_data):
        """Handle connection failure"""
        _LOGGER.error(f"❌ Connection failed: {callback_data}")
        _LOGGER.error(f"❌ Failure details: {type(callback_data)} - {str(callback_data)}")
        self.connected = False
        
        # Check if this might be due to expired AWS MQTT credentials
        error_str = str(callback_data).lower()
        if 'unauthorized' in error_str or 'forbidden' in error_str or 'authentication' in error_str:
            _LOGGER.info("🔄 MQTT connection failure may be due to expired AWS credentials, will refresh on next connection attempt")
            # Clear cached AWS credentials to force refresh on next connection
            self.aws_creds = None
            self.aws_creds_expires_at = None

    def _on_connection_closed(self, callback_data):
        """Handle connection closure"""
        _LOGGER.info(f"📡 Connection closed: {callback_data}")
        _LOGGER.info(f"📡 Disconnect details: {type(callback_data)} - {str(callback_data)}")
        self.connected = False

    def _on_message_received(self, publish_received_data):
        """Handle incoming MQTT messages"""
        publish_packet = publish_received_data.publish_packet
        topic = publish_packet.topic
        payload = publish_packet.payload
        
        try:
            payload_str = payload.decode('utf-8')
            json_payload = json.loads(payload_str)
            
            _LOGGER.info(f"📨 MQTT Message received on topic: {topic}")
            _LOGGER.info(f"📨 Payload size: {len(payload_str)} bytes")
            _LOGGER.info(f"📨 Full payload: {json.dumps(json_payload, indent=2, default=str)}")
            
            # Update shadow state if this is a shadow update
            if 'shadow' in topic and 'state' in json_payload:
                _LOGGER.info(f"🔄 Processing shadow state update...")
                self._update_shadow_state(json_payload)
                _LOGGER.info(f"✅ Shadow state updated, keys: {list(self.last_shadow_state.keys()) if self.last_shadow_state else 'None'}")
            else:
                _LOGGER.info(f"ℹ️  Message on topic {topic} does not contain shadow state data")
                
            # Call registered callbacks
            for callback in self.shadow_callbacks:
                callback(topic, json_payload)
                
        except Exception as e:
            _LOGGER.error(f"❌ Error processing message: {e}")
            _LOGGER.error(f"❌ Raw payload (first 500 chars): {payload[:500]}")
            _LOGGER.error(f"❌ Topic: {topic}")

    def _update_shadow_state(self, shadow_update: Dict[str, Any]):
        """Update internal shadow state from received message"""
        _LOGGER.debug(f"🔄 _update_shadow_state called with: {json.dumps(shadow_update, indent=2, default=str)}")
        
        if 'state' in shadow_update:
            state = shadow_update['state']
            _LOGGER.debug(f"🔄 Found 'state' in shadow update, keys: {list(state.keys())}")
            
            # Look for reported state first, then current state, then fall back to full state
            if 'reported' in state:
                self.last_shadow_state = state['reported']
                _LOGGER.info(f"✅ Updated last_shadow_state from 'reported' with {len(self.last_shadow_state)} keys: {list(self.last_shadow_state.keys())}")
            elif 'current' in state:
                self.last_shadow_state = state['current']
                _LOGGER.info(f"✅ Updated last_shadow_state from 'current' with {len(self.last_shadow_state)} keys: {list(self.last_shadow_state.keys())}")
            else:
                _LOGGER.warning(f"⚠️  No 'reported' or 'current' state found, available keys: {list(state.keys())}")
                # Log the full state structure for debugging
                _LOGGER.debug(f"🔍 Full state structure: {json.dumps(state, indent=2, default=str)}")
        else:
            _LOGGER.warning(f"⚠️  No 'state' found in shadow update, available keys: {list(shadow_update.keys())}")
            # Check if this is a full document update
            if 'current' in shadow_update:
                self.last_shadow_state = shadow_update['current']
                _LOGGER.info(f"✅ Updated last_shadow_state from document 'current' with {len(self.last_shadow_state)} keys: {list(self.last_shadow_state.keys())}")
            elif 'state' not in shadow_update:
                _LOGGER.debug(f"🔍 Full shadow update structure: {json.dumps(shadow_update, indent=2, default=str)}")

    def connect(self, timeout: int = 10) -> bool:
        """
        Connect to AWS IoT and subscribe to device shadow updates.
        
        Args:
            timeout: Connection timeout in seconds
            
        Returns:
            True if connection successful, False otherwise
        """
        _LOGGER.info("🔗 Connecting to AWS IoT...")
        
        try:
            # Ensure we have AWS credentials
            _LOGGER.debug("   Step 1: Ensuring AWS credentials")
            self._ensure_aws_credentials()
            _LOGGER.info("   ✅ AWS credentials ready")
            
            # Create MQTT5 client
            _LOGGER.debug("   Step 2: Creating MQTT5 client")
            _LOGGER.debug(f"   Using host: {self.host}")
            _LOGGER.debug(f"   Using auth name: {self.custom_auth_name}")
            _LOGGER.debug(f"   Token length: {len(self.token) if self.token else 0}")
            _LOGGER.debug(f"   Signature length: {len(self.signature) if self.signature else 0}")
            
            self.mqtt5_client = mqtt5_client_builder.direct_with_custom_authorizer(
                endpoint=self.host,
                auth_authorizer_name=self.custom_auth_name,
                auth_username="",
                auth_password=b"",
                auth_token_key_name="token",
                auth_token_value=self.token,
                auth_authorizer_signature=self.signature,
                client_id=self.client_id,
                on_lifecycle_connection_success=self._on_connection_success,
                on_lifecycle_connection_failure=self._on_connection_failure,
                on_lifecycle_disconnection=self._on_connection_closed,
                on_publish_received=self._on_message_received
            )
            _LOGGER.info("   ✅ MQTT5 client created successfully")
            
            # Start connection
            _LOGGER.debug("   Step 3: Starting connection")
            self.mqtt5_client.start()
            _LOGGER.debug("   ✅ Connection started")
            
            # Wait for connection
            start_time = time.time()
            while not self.connected and (time.time() - start_time) < timeout:
                time.sleep(0.1)
            
            if not self.connected:
                _LOGGER.error("❌ Connection timeout")
                return False
            
            # Subscribe to shadow updates
            self._subscribe_to_shadow_updates()
            
            # Get initial shadow state
            self.get_shadow_state()
            
            _LOGGER.info("✅ Hot tub controller ready")
            return True
            
        except Exception as e:
            _LOGGER.error(f"❌ Connection failed: {e}")
            return False

    def _subscribe_to_shadow_updates(self):
        """Subscribe to device shadow update topics"""
        shadow_topics = [
            f"$aws/things/{self.monitor_id}/shadow/name/state/update/accepted",
            f"$aws/things/{self.monitor_id}/shadow/name/state/update/rejected", 
            f"$aws/things/{self.monitor_id}/shadow/name/state/update/delta",
            f"$aws/things/{self.monitor_id}/shadow/name/state/get/accepted",
            f"$aws/things/{self.monitor_id}/shadow/name/state/update/documents"
        ]
        
        for topic in shadow_topics:
            try:
                self.mqtt5_client.subscribe(
                    subscribe_packet=mqtt5.SubscribePacket(
                        subscriptions=[
                            mqtt5.Subscription(
                                topic_filter=topic,
                                qos=mqtt5.QoS.AT_LEAST_ONCE,
                            )
                        ]
                    )
                )
                time.sleep(0.05)
            except Exception as e:
                _LOGGER.warning(f"⚠️  Failed to subscribe to {topic}: {e}")

    def _publish_shadow_update(self, desired_state: Dict[str, Any], description: str = "") -> bool:
        """
        Publish an update to the device shadow.
        
        Args:
            desired_state: The desired state to set
            description: Optional description for logging
            
        Returns:
            True if publish successful, False otherwise
        """
        if not self.connected:
            _LOGGER.error("❌ Not connected to AWS IoT")
            return False
        
        topic = f"$aws/things/{self.monitor_id}/shadow/name/state/update"
        payload = {
            "state": {
                "desired": desired_state
            },
            "clientToken": f"{int(time.time())}-{self.client_id}"
        }
        
        try:
            publish_packet = mqtt5.PublishPacket(
                topic=topic,
                payload=json.dumps(payload).encode('utf-8'),
                qos=mqtt5.QoS.AT_LEAST_ONCE
            )
            
            self.mqtt5_client.publish(publish_packet)
            
            if description:
                _LOGGER.info(f"📤 {description}")
            
            return True
            
        except Exception as e:
            _LOGGER.error(f"❌ Failed to publish shadow update: {e}")
            return False

    def get_shadow_state(self) -> bool:
        """
        Request current shadow state from AWS IoT.
        
        Returns:
            True if request sent successfully, False otherwise
        """
        if not self.connected:
            return False
        
        topic = f"$aws/things/{self.monitor_id}/shadow/name/state/get"
        
        try:
            publish_packet = mqtt5.PublishPacket(
                topic=topic,
                payload=b"{}",
                qos=mqtt5.QoS.AT_LEAST_ONCE
            )
            
            self.mqtt5_client.publish(publish_packet)
            return True
            
        except Exception as e:
            _LOGGER.error(f"❌ Failed to get shadow state: {e}")
            return False

    # Temperature Control Methods
    
    def set_temperature(self, temperature: int) -> bool:
        """
        Set the hot tub target temperature.
        
        Args:
            temperature: Target temperature in Celsius
            
        Returns:
            True if command sent successfully, False otherwise
        """
        desired_state = {
            "zones": {
                "temperatureControl": {
                    "1": {
                        "setPoint": temperature
                    }
                }
            }
        }
        
        return self._publish_shadow_update(
            desired_state, 
            f"🌡️ Setting temperature to {temperature}°C"
        )

    def get_temperature(self) -> Optional[TemperatureStatus]:
        """
        Get current temperature status.
        
        Returns:
            TemperatureStatus object or None if not available
        """
        if not self.last_shadow_state:
            return None
        
        try:
            temp_control = self.last_shadow_state.get('zones', {}).get('temperatureControl', {}).get('1', {})
            
            return TemperatureStatus(
                current_temp=temp_control.get('temperature_', 0),
                set_point=temp_control.get('setPoint', 0),
                heating_status=temp_control.get('status_', 0),
                eco_mode=temp_control.get('mode_', {}).get('eco', False),
                flow_status=temp_control.get('flo_', 'UNKNOWN')
            )
            
        except Exception as e:
            _LOGGER.warning(f"⚠️  Error reading temperature: {e}")
            return None

    def set_eco_mode(self, enabled: bool) -> bool:
        """
        Enable or disable eco heating mode.
        
        Args:
            enabled: True to enable eco mode, False to disable
            
        Returns:
            True if command sent successfully, False otherwise
        """
        desired_state = {
            "zones": {
                "temperatureControl": {
                    "1": {
                        "mode_": {
                            "eco": enabled
                        }
                    }
                }
            }
        }
        
        return self._publish_shadow_update(
            desired_state,
            f"♻️ {'Enabling' if enabled else 'Disabling'} eco mode"
        )

    # Lighting Control Methods
    
    def turn_on_lights(self, zone: int = 1) -> bool:
        """
        Turn on hot tub lights.
        
        Args:
            zone: Light zone number (default: 1)
            
        Returns:
            True if command sent successfully, False otherwise
        """
        return self.set_light_state(zone, True)

    def turn_off_lights(self, zone: int = 1) -> bool:
        """
        Turn off hot tub lights.
        
        Args:
            zone: Light zone number (default: 1)
            
        Returns:
            True if command sent successfully, False otherwise
        """
        return self.set_light_state(zone, False)

    def set_light_state(self, zone: int, active: bool) -> bool:
        """
        Set the state of a lighting zone.
        
        Args:
            zone: Light zone number
            active: True to turn on, False to turn off
            
        Returns:
            True if command sent successfully, False otherwise
        """
        desired_state = {
            "zones": {
                "lighting": {
                    str(zone): {
                        "active": active
                    }
                }
            }
        }
        
        return self._publish_shadow_update(
            desired_state,
            f"💡 Turning light zone {zone} {'ON' if active else 'OFF'}"
        )

    def get_light_status(self) -> Dict[int, bool]:
        """
        Get current status of all lighting zones.
        
        Returns:
            Dictionary mapping zone numbers to on/off status
        """
        if not self.last_shadow_state:
            return {}
        
        try:
            lighting = self.last_shadow_state.get('zones', {}).get('lighting', {})
            return {int(k): v.get('active', False) for k, v in lighting.items()}
        except Exception as e:
            _LOGGER.warning(f"⚠️  Error reading light status: {e}")
            return {}

    # Pump/Flow Control Methods
    
    def start_pump(self, zone: int, speed: int = 100) -> bool:
        """
        Start a pump/flow zone.
        
        Args:
            zone: Flow zone number (1-3)
            speed: Pump speed percentage (0-100)
            
        Returns:
            True if command sent successfully, False otherwise
        """
        return self.set_pump_state(zone, True, speed)

    def stop_pump(self, zone: int) -> bool:
        """
        Stop a pump/flow zone.
        
        Args:
            zone: Flow zone number (1-3)
            
        Returns:
            True if command sent successfully, False otherwise
        """
        return self.set_pump_state(zone, False)

    def set_pump_state(self, zone: int, active: bool, speed: int = 100) -> bool:
        """
        Set the state and speed of a flow/pump zone.
        
        Args:
            zone: Flow zone number (1-3)
            active: True to start, False to stop
            speed: Pump speed percentage (0-100)
            
        Returns:
            True if command sent successfully, False otherwise
        """
        desired_state = {
            "zones": {
                "flow": {
                    str(zone): {
                        "active": active,
                        "speed": speed if active else 100
                    }
                }
            }
        }
        
        action = f"Starting at {speed}%" if active else "Stopping"
        return self._publish_shadow_update(
            desired_state,
            f"🌀 Pump zone {zone}: {action}"
        )

    def set_pump_speed(self, zone: int, speed: int) -> bool:
        """
        Set the speed of a pump/flow zone (without changing on/off state).
        
        Args:
            zone: Flow zone number (1-3)
            speed: Pump speed percentage (0-100)
            
        Returns:
            True if command sent successfully, False otherwise
        """
        desired_state = {
            "zones": {
                "flow": {
                    str(zone): {
                        "speed": speed
                    }
                }
            }
        }
        
        return self._publish_shadow_update(
            desired_state,
            f"⚡ Setting pump zone {zone} speed to {speed}%"
        )

    def get_pump_status(self) -> List[FlowZoneInfo]:
        """
        Get current status of all pump/flow zones.
        
        Returns:
            List of FlowZoneInfo objects
        """
        if not self.last_shadow_state:
            return []
        
        try:
            flow_zones = self.last_shadow_state.get('zones', {}).get('flow', {})
            result = []
            
            for zone_id, zone_data in flow_zones.items():
                result.append(FlowZoneInfo(
                    zone_id=int(zone_id),
                    active=zone_data.get('active', False),
                    speed=zone_data.get('speed', 100),
                    initiators=zone_data.get('initiators_', [])
                ))
            
            return result
            
        except Exception as e:
            _LOGGER.warning(f"⚠️  Error reading pump status: {e}")
            return []

    # System Status Methods
    
    def get_system_status(self) -> Optional[SystemStatus]:
        """
        Get comprehensive system status.
        
        Returns:
            SystemStatus object or None if not available
        """
        if not self.last_shadow_state:
            return None
        
        try:
            # Connectivity status
            connectivity_data = self.last_shadow_state.get('connectivity_', {})
            features = self.last_shadow_state.get('features', {})
            rf = features.get('rf', {})
            
            connectivity = ConnectivityStatus(
                gateway_status=connectivity_data.get('gatewayStatus', 'UNKNOWN'),
                vessel_status=connectivity_data.get('vesselStatus', 'UNKNOWN'),
                rf_channel=rf.get('channel', 0),
                rf_strength=rf.get('strength_', 0)
            )
            
            # Temperature status
            temperature = self.get_temperature()
            
            # Flow zones status  
            flow_zones = self.get_pump_status()
            
            # Lighting status
            lighting_zones = self.get_light_status()
            
            # Operation mode
            operation_mode = features.get('operationMode', 0)
            
            return SystemStatus(
                connectivity=connectivity,
                temperature=temperature,
                flow_zones=flow_zones,
                lighting_zones=lighting_zones,
                operation_mode=operation_mode
            )
            
        except Exception as e:
            _LOGGER.warning(f"⚠️  Error reading system status: {e}")
            return None

    def get_connectivity_status(self) -> Optional[ConnectivityStatus]:
        """
        Get system connectivity status.
        
        Returns:
            ConnectivityStatus object or None if not available
        """
        if not self.last_shadow_state:
            return None
        
        try:
            connectivity_data = self.last_shadow_state.get('connectivity_', {})
            features = self.last_shadow_state.get('features', {})
            rf = features.get('rf', {})
            
            return ConnectivityStatus(
                gateway_status=connectivity_data.get('gatewayStatus', 'UNKNOWN'),
                vessel_status=connectivity_data.get('vesselStatus', 'UNKNOWN'),
                rf_channel=rf.get('channel', 0),
                rf_strength=rf.get('strength_', 0)
            )
            
        except Exception as e:
            _LOGGER.warning(f"⚠️  Error reading connectivity: {e}")
            return None

    # Utility Methods
    
    def register_shadow_callback(self, callback):
        """
        Register a callback function to receive shadow updates.
        
        Args:
            callback: Function that takes (topic, payload) arguments
        """
        self.shadow_callbacks.append(callback)

    def wait_for_update(self, timeout: int = 5) -> bool:
        """
        Wait for a shadow update to be received.
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            True if update received, False if timeout
        """
        start_time = time.time()
        initial_state = self.last_shadow_state.copy()
        
        while (time.time() - start_time) < timeout:
            if self.last_shadow_state != initial_state:
                return True
            time.sleep(0.1)
        
        return False

    def disconnect(self):
        """Disconnect from AWS IoT"""
        if self.mqtt5_client:
            _LOGGER.info("📡 Disconnecting from AWS IoT...")
            try:
                self.mqtt5_client.stop()
                self.connected = False
                _LOGGER.info("✅ Disconnected successfully")
            except Exception as e:
                _LOGGER.warning(f"⚠️  Disconnect error: {e}")

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()

    # Convenience Methods
    
    def quick_status(self) -> str:
        """
        Get a quick status summary as a formatted string.
        
        Returns:
            Formatted status string
        """
        temp = self.get_temperature()
        lights = self.get_light_status()
        pumps = self.get_pump_status()
        connectivity = self.get_connectivity_status()
        
        status_lines = ["🏊‍♀️ Hot Tub Status:"]
        
        if temp:
            status_lines.append(f"   🌡️  Temperature: {temp.current_temp}°C (target: {temp.set_point}°C)")
            status_lines.append(f"   ♻️  Eco Mode: {'ON' if temp.eco_mode else 'OFF'}")
        
        if lights:
            light_status = ", ".join([f"Zone {k}: {'ON' if v else 'OFF'}" for k, v in lights.items()])
            status_lines.append(f"   💡 Lights: {light_status}")
        
        if pumps:
            pump_status = ", ".join([f"Zone {p.zone_id}: {'ON' if p.active else 'OFF'} ({p.speed}%)" for p in pumps])
            status_lines.append(f"   🌀 Pumps: {pump_status}")
        
        if connectivity:
            status_lines.append(f"   📡 Status: {connectivity.vessel_status} (RF: {connectivity.rf_strength}/5)")
        
        return "\n".join(status_lines)

# Example usage and testing
if __name__ == "__main__":
    # NOTE: This example uses the legacy broker_url method for testing
    # In production, use the OAuth token method with proper monitor_id from API
    
    # Example broker URL - replace with your actual URL (this is just an example format)
    # WARNING: Never commit real broker URLs as they contain sensitive authentication data
    broker_url = "wss://your-iot-endpoint.iot.us-east-1.amazonaws.com/mqtt?x-amz-customauthorizer-name=YourCustomAuthorizer&token=YOUR_TOKEN&x-amz-customauthorizer-signature=YOUR_SIGNATURE"
    
    # For production use with OAuth tokens:
    # controller = GeckoHotTubController(
    #     access_token="your_oauth_access_token",
    #     refresh_token="your_oauth_refresh_token",
    #     monitor_id="your_monitor_id_from_api"
    # )
    
    print("🧪 Testing Gecko Hot Tub Controller")
    print("=" * 50)
    print("⚠️  This is a development test using legacy broker URL method")
    print("⚠️  Replace with OAuth tokens and API-obtained monitor_id for production")
    
    try:
        # Initialize controller (legacy mode for testing)
        controller = GeckoHotTubController(broker_url)
        
        # Connect
        if controller.connect():
            print("\n" + controller.quick_status())
            
            # Example operations (uncomment to test)
            # controller.set_temperature(40)
            # controller.turn_on_lights()
            # controller.start_pump(1, speed=75)
            
            time.sleep(2)  # Wait for updates
            
            print("\nAfter operations:")
            print(controller.quick_status())
            
        controller.disconnect()
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
