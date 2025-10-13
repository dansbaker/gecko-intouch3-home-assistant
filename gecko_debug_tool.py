#!/usr/bin/env python3
"""
Gecko Integration Debug Tool

Comprehensive tool that:
1. Authenticates with Gecko API
2. Fetches account, vessel, and spa configuration
3. Connects to MQTT and captures shadow states
4. Saves everything to a debug report file

Usage:
    python gecko_debug_tool.py --username your@email.com [--duration 60]
"""

import asyncio
import json
import logging
import secrets
import hashlib
import base64
import argparse
import getpass
from datetime import datetime
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs

import aiohttp
from awscrt import mqtt5
from awsiot import mqtt5_client_builder

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
_LOGGER = logging.getLogger(__name__)


class StandaloneAuth0Client:
    """Auth0 client for standalone authentication without Home Assistant."""
    
    def __init__(self):
        self.auth0_domain = "gecko-prod.us.auth0.com"
        self.client_id = "IlbhNGMeYfb8ovs0gK43CjPybltA3ogH"
        self.audience = "https://api.geckowatermonitor.com"
        self.redirect_uri = "com.geckoportal.gecko://gecko-prod.us.auth0.com/capacitor/com.geckoportal.gecko/callback"
    
    async def authenticate(self, username: str, password: str) -> Dict[str, str]:
        """Authenticate and return tokens."""
        # Generate PKCE parameters
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        async with aiohttp.ClientSession() as session:
            # Step 1: Get authorization state
            state = await self._get_auth_state(session, code_challenge)
            
            # Step 2: Submit credentials
            auth_code = await self._submit_credentials(session, username, password, state)
            
            # Step 3: Exchange code for tokens
            tokens = await self._exchange_code_for_tokens(session, auth_code, code_verifier)
            
            return tokens
    
    async def _get_auth_state(self, session: aiohttp.ClientSession, code_challenge: str) -> str:
        """Get auth state from authorization endpoint."""
        import urllib.parse
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml',
            'Accept-Language': 'en-GB,en;q=0.9',
        }
        
        auth_params = {
            "client_id": self.client_id,
            "scope": "openid profile email offline_access",
            "display": "touch",
            "audience": self.audience,
            "redirect_uri": self.redirect_uri,
            "prompt": "login",
            "response_type": "code",
            "response_mode": "query",
            "state": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('='),
            "nonce": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('='),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "auth0Client": base64.b64encode('{"name":"auth0-vue","version":"2.3.1"}'.encode()).decode()
        }
        
        auth_url = f"https://{self.auth0_domain}/authorize?" + urllib.parse.urlencode(auth_params)
        
        async with session.get(auth_url, headers=headers, allow_redirects=True) as response:
            if response.status != 200:
                raise Exception(f"Failed to get authorization page: HTTP {response.status}")
            
            final_url = str(response.url)
            
            # Extract state from URL
            if "/u/login?state=" in final_url:
                import re
                state_match = re.search(r'state=([^&]+)', final_url)
                if state_match:
                    state = urllib.parse.unquote(state_match.group(1))
                    return state
            
            raise Exception("Failed to extract state from authorization flow")
    
    async def _submit_credentials(self, session: aiohttp.ClientSession, username: str, password: str, state: str) -> str:
        """Submit credentials and get authorization code."""
        import urllib.parse
        login_url = f"https://{self.auth0_domain}/u/login"
        login_params = {"state": state}
        
        login_data = {
            'state': state,
            'username': username,
            'password': password,
            'action': 'default'
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': f'https://{self.auth0_domain}',
            'Referer': f'{login_url}?{urllib.parse.urlencode(login_params)}',
        }
        
        async with session.post(login_url, params=login_params, data=login_data, headers=headers, allow_redirects=False) as response:
            if response.status not in [302, 303]:
                error_text = await response.text()
                raise Exception(f"Login failed: HTTP {response.status} - {error_text}")
            
            # Follow redirects to get authorization code
            location = response.headers.get('Location', '')
            
            # Handle relative URLs
            if location.startswith('/'):
                location = f"https://{self.auth0_domain}{location}"
            
            # Follow the redirect chain
            async with session.get(location, allow_redirects=False) as redir_response:
                final_location = redir_response.headers.get('Location', '')
                
                # Extract authorization code from redirect
                import re
                code_match = re.search(r'code=([^&]+)', final_location)
                if code_match:
                    auth_code = urllib.parse.unquote(code_match.group(1))
                    return auth_code
                
                raise Exception(f"No authorization code in redirect: {final_location}")
    
    async def _exchange_code_for_tokens(self, session: aiohttp.ClientSession, auth_code: str, code_verifier: str) -> Dict[str, str]:
        """Exchange authorization code for access tokens."""
        token_url = f"https://{self.auth0_domain}/oauth/token"
        
        token_data = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": auth_code,
            "code_verifier": code_verifier,
            "redirect_uri": self.redirect_uri,
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        
        async with session.post(token_url, data=token_data, headers=headers) as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"Token exchange failed: {error_text}")
            
            return await response.json()


class GeckoDebugTool:
    """Comprehensive debug tool for Gecko integration."""
    
    def __init__(self, username: str, password: str, output_file: str = None, redact_pii: bool = True):
        self.username = username
        self.password = password
        self.output_file = output_file or f"gecko_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.redact_pii_enabled = redact_pii
        
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.account_id: Optional[int] = None
        self.monitor_id: Optional[str] = None
        self.vessel_name: Optional[str] = None
        self.aws_credentials: Optional[Dict[str, Any]] = None
        self.spa_config: Optional[Dict[str, Any]] = None
        
        self.mqtt_client: Optional[Any] = None
        self.connected = False
        self.message_count = 0
        
        # Store all debug data
        self.debug_data = {
            "timestamp": datetime.now().isoformat(),
            "username": "[REDACTED]" if self.redact_pii_enabled else self.username,
            "authentication": {},
            "account": {},
            "vessel": {},
            "spa_configuration": {},
            "aws_credentials": {},
            "mqtt_messages": []
        }
        
        # Generate client ID
        random_hex = secrets.token_hex(8)
        self.client_id = f"gecko-debug-{random_hex}"
    
    def _redact_pii(self, data: Any, path: str = "") -> Any:
        """Recursively redact PII from data structures."""
        # If redaction is disabled, return data as-is
        if not self.redact_pii_enabled:
            return data
            
        if isinstance(data, dict):
            redacted = {}
            for key, value in data.items():
                lower_key = key.lower()
                # Check if key contains PII
                if any(pii_field in lower_key for pii_field in [
                    'email', 'username', 'password', 'userid', 'accountid', 
                    'vesselid', 'monitorid', 'location', 'address', 'phone',
                    'firstname', 'lastname', 'name', 'city', 'state', 'zip',
                    'postal', 'country', 'latitude', 'longitude', 'timezone',
                    'url', 'map', 'staticimage', 'mapsurl'
                ]):
                    # Redact but preserve structure
                    if isinstance(value, str):
                        # Check if it's a URL with coordinates
                        if 'maps.googleapis.com' in value or 'maps.google.com' in value or 'maps/@' in value:
                            redacted[key] = "[REDACTED - MAP URL WITH COORDINATES]"
                        else:
                            redacted[key] = "[REDACTED]"
                    elif isinstance(value, (int, float)):
                        redacted[key] = 0
                    elif isinstance(value, dict):
                        redacted[key] = {k: "[REDACTED]" for k in value.keys()}
                    elif isinstance(value, list):
                        redacted[key] = []
                    else:
                        redacted[key] = "[REDACTED]"
                else:
                    # Check if value is a string containing coordinate patterns
                    if isinstance(value, str):
                        # Check for URLs with GPS coordinates
                        if ('maps.googleapis.com' in value or 'maps.google.com' in value or 'google.com/maps' in value) and ('center=' in value or '@' in value):
                            redacted[key] = "[REDACTED - MAP URL WITH COORDINATES]"
                        else:
                            # Recursively process nested structures
                            redacted[key] = self._redact_pii(value, f"{path}.{key}" if path else key)
                    else:
                        # Recursively process nested structures
                        redacted[key] = self._redact_pii(value, f"{path}.{key}" if path else key)
            return redacted
        elif isinstance(data, list):
            return [self._redact_pii(item, path) for item in data]
        else:
            return data
    
    async def run(self, duration: Optional[int] = None):
        """Run the complete debug process."""
        try:
            _LOGGER.info("🦎 Gecko Integration Debug Tool")
            _LOGGER.info("="*80)
            
            # Step 1: Authenticate
            _LOGGER.info("🔐 Authenticating...")
            if not await self.authenticate():
                _LOGGER.error("❌ Authentication failed")
                return False
            
            # Step 2: Discover account and vessel
            _LOGGER.info("🔍 Discovering account and vessel...")
            if not await self.discover_account():
                _LOGGER.error("❌ Account discovery failed")
                return False
            
            # Step 3: Get spa configuration
            _LOGGER.info("⚙️  Fetching spa configuration...")
            if not await self.get_spa_configuration():
                _LOGGER.error("❌ Failed to get spa configuration")
                return False
            
            # Step 4: Get AWS credentials
            _LOGGER.info("🔑 Getting AWS credentials...")
            if not await self.get_aws_credentials():
                _LOGGER.error("❌ Failed to get AWS credentials")
                return False
            
            # Step 5: Connect to MQTT
            _LOGGER.info("📡 Connecting to MQTT...")
            if not await self.connect_mqtt():
                _LOGGER.error("❌ MQTT connection failed")
                return False
            
            # Step 6: Monitor MQTT messages
            if duration:
                _LOGGER.info(f"⏱️  Monitoring MQTT for {duration} seconds...")
                await asyncio.sleep(duration)
            else:
                _LOGGER.info("⏱️  Monitoring MQTT indefinitely (Ctrl+C to stop)...")
                try:
                    while True:
                        await asyncio.sleep(1)
                except KeyboardInterrupt:
                    _LOGGER.info("⚠️  Stopped by user")
            
            return True
            
        except Exception as e:
            _LOGGER.error(f"❌ Error: {e}", exc_info=True)
            self.debug_data["error"] = str(e)
            return False
        finally:
            await self.cleanup()
            await self.save_debug_data()
    
    async def authenticate(self) -> bool:
        """Authenticate with Gecko API."""
        try:
            auth_client = StandaloneAuth0Client()
            tokens = await auth_client.authenticate(self.username, self.password)
            
            self.access_token = tokens.get("access_token")
            self.refresh_token = tokens.get("refresh_token")
            
            self.debug_data["authentication"] = {
                "success": True,
                "access_token_length": len(self.access_token) if self.access_token else 0,
                "refresh_token_length": len(self.refresh_token) if self.refresh_token else 0,
                "expires_in": tokens.get("expires_in"),
                "token_type": tokens.get("token_type")
            }
            
            _LOGGER.info("✅ Authentication successful")
            return True
            
        except Exception as e:
            _LOGGER.error(f"❌ Authentication failed: {e}")
            self.debug_data["authentication"] = {
                "success": False,
                "error": str(e)
            }
            return False
    
    async def discover_account(self) -> bool:
        """Discover account and vessel information."""
        try:
            # Decode JWT to get user info
            header, payload, signature = self.access_token.split('.')
            payload += '=' * (-len(payload) % 4)
            decoded_payload = base64.urlsafe_b64decode(payload)
            token_data = json.loads(decoded_payload)
            user_id = token_data.get("sub")
            
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json",
            }
            
            async with aiohttp.ClientSession() as session:
                # Step 1: PUT /v2/users
                user_url = "https://api.geckowatermonitor.com/v2/users"
                user_payload = {
                    "user": {
                        "userId": user_id,
                        "email": self.username
                    },
                    "deviceInfo": {
                        "deviceId": "gecko-debug-tool",
                        "platform": "android",
                        "operatingSystem": "android",
                        "model": "Debug Tool",
                        "manufacturer": "gecko-debug",
                        "osVersion": "13",
                        "appVersion": "3.7.1",
                        "appBuild": "168"
                    }
                }
                
                async with session.put(user_url, headers=headers, json=user_payload) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"User endpoint failed: {error_text}")
                    
                    data = await response.json()
                    account = data.get("account", {})
                    self.account_id = account.get("accountId")
                    
                    self.debug_data["account"] = self._redact_pii(account)
                    _LOGGER.info(f"✅ Account ID: {self.account_id}")
                
                # Step 2: GET /v3/accounts/{id}/vessels
                vessels_url = f"https://api.geckowatermonitor.com/v3/accounts/{self.account_id}/vessels"
                params = {"customActionsVersion": "5"}
                
                async with session.get(vessels_url, headers=headers, params=params) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"Vessels endpoint failed: {error_text}")
                    
                    data = await response.json()
                    vessels = data.get("vessels", [])
                    
                    if not vessels:
                        raise Exception("No vessels found")
                    
                    vessel = vessels[0]
                    self.monitor_id = vessel.get("monitorId")
                    self.vessel_name = vessel.get("name", "Unknown")
                    
                    self.debug_data["vessel"] = self._redact_pii(vessel)
                    _LOGGER.info(f"✅ Vessel: {self.vessel_name} (Monitor ID: {self.monitor_id})")
                
                return True
                
        except Exception as e:
            _LOGGER.error(f"❌ Account discovery failed: {e}")
            self.debug_data["account"]["error"] = str(e)
            return False
    
    async def get_spa_configuration(self) -> bool:
        """Get spa configuration."""
        try:
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json",
            }
            
            spa_config_url = f"https://api.geckowatermonitor.com/accounts/{self.account_id}/monitors/{self.monitor_id}/spa-configuration"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(spa_config_url, headers=headers) as response:
                    if response.status == 200:
                        self.spa_config = await response.json()
                        self.debug_data["spa_configuration"] = self.spa_config
                        
                        # Log summary
                        accessories = self.spa_config.get("accessories", {})
                        _LOGGER.info("✅ Spa Configuration:")
                        _LOGGER.info(f"   - Pumps: {len(accessories.get('pumps', {}))}")
                        _LOGGER.info(f"   - Lights: {len(accessories.get('lights', {}))}")
                        _LOGGER.info(f"   - Waterfalls: {len(accessories.get('waterfalls', {}))}")
                        _LOGGER.info(f"   - Blowers: {len(accessories.get('blowers', {}))}")
                        
                        return True
                    else:
                        error_text = await response.text()
                        raise Exception(f"Status {response.status}: {error_text}")
                        
        except Exception as e:
            _LOGGER.error(f"❌ Failed to get spa configuration: {e}")
            self.debug_data["spa_configuration"]["error"] = str(e)
            return False
    
    async def get_aws_credentials(self) -> bool:
        """Get AWS credentials."""
        try:
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json",
            }
            
            livestream_url = f"https://api.geckowatermonitor.com/v2/monitors/{self.monitor_id}/liveStream"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(livestream_url, headers=headers) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"Status {response.status}: {error_text}")
                    
                    self.aws_credentials = await response.json()
                    
                    # Optionally redact AWS credentials for security
                    if self.redact_pii_enabled:
                        self.debug_data["aws_credentials"] = {
                            "redacted": True,
                            "note": "AWS IoT credentials redacted for security. Includes broker URL, auth tokens, and topic grants."
                        }
                    else:
                        self.debug_data["aws_credentials"] = self.aws_credentials
                    
                    _LOGGER.info("✅ AWS credentials obtained")
                    return True
                    
        except Exception as e:
            _LOGGER.error(f"❌ Failed to get AWS credentials: {e}")
            self.debug_data["aws_credentials"]["error"] = str(e)
            return False
    
    async def connect_mqtt(self) -> bool:
        """Connect to MQTT broker."""
        try:
            broker_url = self.aws_credentials.get("brokerUrl")
            parsed = urlparse(broker_url)
            host = parsed.hostname
            port = parsed.port or 443
            
            params = parse_qs(parsed.query)
            custom_auth_name = params.get('x-amz-customauthorizer-name', [None])[0]
            token = params.get('token', [None])[0]
            signature = params.get('x-amz-customauthorizer-signature', [None])[0]
            
            if not all([host, custom_auth_name, token, signature]):
                raise Exception("Missing required parameters in broker URL")
            
            # Build MQTT5 client
            self.mqtt_client = mqtt5_client_builder.direct_with_custom_authorizer(
                endpoint=host,
                auth_authorizer_name=custom_auth_name,
                auth_username="",
                auth_password=b"",
                auth_token_key_name="token",
                auth_token_value=token,
                auth_authorizer_signature=signature,
                client_id=self.client_id,
                on_publish_received=self._on_message_received,
                on_lifecycle_connection_success=self._on_lifecycle_event,
                on_lifecycle_stopped=self._on_lifecycle_stopped,
                on_lifecycle_disconnection=self._on_lifecycle_disconnection,
            )
            
            self.mqtt_client.start()
            
            # Wait for connection
            for i in range(30):
                if self.connected:
                    break
                await asyncio.sleep(0.5)
            
            if not self.connected:
                raise Exception("Connection timeout")
            
            # Subscribe to shadow topics
            await self._subscribe_to_shadow_topics()
            
            _LOGGER.info("✅ MQTT connected and subscribed")
            return True
            
        except Exception as e:
            _LOGGER.error(f"❌ MQTT connection failed: {e}")
            self.debug_data["mqtt_connection_error"] = str(e)
            return False
    
    async def _subscribe_to_shadow_topics(self):
        """Subscribe to shadow topics."""
        shadow_topics = [
            f"$aws/things/{self.monitor_id}/shadow/name/state/update/accepted",
            f"$aws/things/{self.monitor_id}/shadow/name/state/update/rejected",
            f"$aws/things/{self.monitor_id}/shadow/name/state/update/delta",
            f"$aws/things/{self.monitor_id}/shadow/name/state/get/accepted",
            f"$aws/things/{self.monitor_id}/shadow/name/state/update/documents"
        ]
        
        for topic in shadow_topics:
            try:
                subscribe_packet = mqtt5.SubscribePacket(
                    subscriptions=[
                        mqtt5.Subscription(
                            topic_filter=topic,
                            qos=mqtt5.QoS.AT_LEAST_ONCE
                        )
                    ]
                )
                subscribe_future = self.mqtt_client.subscribe(subscribe_packet)
                await asyncio.wrap_future(subscribe_future)
                await asyncio.sleep(0.05)
            except Exception as e:
                _LOGGER.warning(f"⚠️  Failed to subscribe to {topic}: {e}")
        
        # Request initial shadow state
        get_topic = f"$aws/things/{self.monitor_id}/shadow/name/state/get"
        try:
            publish_packet = mqtt5.PublishPacket(
                topic=get_topic,
                payload=json.dumps({}).encode('utf-8'),
                qos=mqtt5.QoS.AT_LEAST_ONCE
            )
            publish_future = self.mqtt_client.publish(publish_packet)
            await asyncio.wrap_future(publish_future)
        except Exception as e:
            _LOGGER.warning(f"⚠️  Failed to request initial shadow state: {e}")
    
    def _on_lifecycle_event(self, lifecycle_event: mqtt5.LifecycleConnectSuccessData):
        """Handle MQTT connection."""
        _LOGGER.info("🔌 MQTT connection established")
        self.connected = True
    
    def _on_lifecycle_stopped(self, lifecycle_stopped: mqtt5.LifecycleStoppedData):
        """Handle MQTT disconnection."""
        _LOGGER.warning("🔌 MQTT connection stopped")
        self.connected = False
    
    def _on_lifecycle_disconnection(self, lifecycle_disconnect: mqtt5.LifecycleDisconnectData):
        """Handle MQTT disconnection."""
        _LOGGER.warning("🔌 MQTT disconnected")
        self.connected = False
    
    def _on_message_received(self, message: mqtt5.PublishReceivedData):
        """Handle incoming MQTT messages."""
        try:
            topic = message.publish_packet.topic
            payload = message.publish_packet.payload
            
            if payload:
                payload_str = payload.decode('utf-8')
                payload_json = json.loads(payload_str)
                
                self.message_count += 1
                timestamp = datetime.now().isoformat()
                
                # Optionally redact monitor ID from topic
                redacted_topic = topic
                if self.redact_pii_enabled and self.monitor_id:
                    redacted_topic = topic.replace(str(self.monitor_id), "[MONITOR_ID]")
                
                # Store message
                message_data = {
                    "message_number": self.message_count,
                    "timestamp": timestamp,
                    "topic": redacted_topic,
                    "payload": self._redact_pii(payload_json)
                }
                self.debug_data["mqtt_messages"].append(message_data)
                
                # Log summary
                _LOGGER.info(f"📨 Message #{self.message_count} on {redacted_topic}")
                
        except Exception as e:
            _LOGGER.error(f"❌ Error processing message: {e}", exc_info=True)
    
    async def cleanup(self):
        """Clean up resources."""
        _LOGGER.info("🧹 Cleaning up...")
        if self.mqtt_client:
            try:
                self.mqtt_client.stop()
                await asyncio.sleep(1)
            except Exception as e:
                _LOGGER.warning(f"Error stopping MQTT client: {e}")
    
    async def save_debug_data(self):
        """Save debug data to file."""
        try:
            self.debug_data["summary"] = {
                "total_mqtt_messages": self.message_count,
                "authentication_success": self.debug_data["authentication"].get("success", False),
                "spa_config_retrieved": bool(self.spa_config),
                "mqtt_connected": self.message_count > 0
            }
            
            with open(self.output_file, 'w') as f:
                json.dump(self.debug_data, f, indent=2, default=str)
            
            _LOGGER.info(f"💾 Debug data saved to: {self.output_file}")
            _LOGGER.info(f"📊 Summary:")
            _LOGGER.info(f"   - Authentication: {'✅' if self.debug_data['authentication'].get('success') else '❌'}")
            _LOGGER.info(f"   - Spa Configuration: {'✅' if self.spa_config else '❌'}")
            _LOGGER.info(f"   - MQTT Messages: {self.message_count}")
            
        except Exception as e:
            _LOGGER.error(f"❌ Failed to save debug data: {e}")


async def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Gecko Integration Debug Tool")
    parser.add_argument(
        "--username",
        "-u",
        required=True,
        help="Gecko account username/email"
    )
    parser.add_argument(
        "--password",
        "-p",
        help="Gecko account password (will prompt if not provided)"
    )
    parser.add_argument(
        "--duration",
        "-d",
        type=int,
        default=30,
        help="Duration to monitor MQTT in seconds (default: 30)"
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file name (default: gecko_debug_TIMESTAMP.json)"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose debug logging"
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Disable PII redaction (WARNING: output will contain sensitive information)"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Get password if not provided
    password = args.password
    if not password:
        password = getpass.getpass("Password: ")
    
    # Create and run debug tool
    tool = GeckoDebugTool(args.username, password, args.output, redact_pii=not args.no_redact)
    
    try:
        await tool.run(args.duration)
    except KeyboardInterrupt:
        _LOGGER.info("\n⚠️  Interrupted by user")
    except Exception as e:
        _LOGGER.error(f"❌ Error: {e}", exc_info=True)


if __name__ == "__main__":
    asyncio.run(main())
