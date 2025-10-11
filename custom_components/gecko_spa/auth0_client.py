"""Auth0 client for Gecko authentication."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import secrets
import urllib.parse
from typing import Any, Dict

import aiohttp

from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

class GeckoAuth0Error(Exception):
    """Base exception for Auth0 authentication errors."""


class GeckoAuth0InvalidCredentials(GeckoAuth0Error):
    """Exception for invalid username/password."""


class GeckoAuth0ConnectionError(GeckoAuth0Error):
    """Exception for connection/network errors."""


class GeckoAuth0RateLimitError(GeckoAuth0Error):
    """Exception for rate limiting errors."""


class GeckoAuth0Client:
    """Handles Gecko Auth0 authentication flow."""
    
    def __init__(self, hass: HomeAssistant):
        """Initialize the Auth0 client."""
        self.hass = hass
        self.auth0_domain = "gecko-prod.us.auth0.com"
        self.client_id = "IlbhNGMeYfb8ovs0gK43CjPybltA3ogH"
        self.audience = "https://api.geckowatermonitor.com"
        self.redirect_uri = "com.geckoportal.gecko://gecko-prod.us.auth0.com/capacitor/com.geckoportal.gecko/callback"
        
    async def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate with Auth0 using username/password.
        
        Args:
            username: Gecko app username (email)
            password: Gecko app password
            
        Returns:
            Dictionary containing access_token, refresh_token, expires_in, etc.
            
        Raises:
            GeckoAuth0InvalidCredentials: If credentials are invalid
            GeckoAuth0ConnectionError: If network/connection fails
            GeckoAuth0RateLimitError: If rate limited by Auth0
            GeckoAuth0Error: For other authentication errors
        """
        _LOGGER.info("Starting Auth0 authentication for user: %s", username)
        
        try:
            # Generate PKCE parameters (like mobile app would)
            code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode('utf-8')).digest()
            ).decode('utf-8').rstrip('=')
            
            _LOGGER.debug("Generated PKCE parameters for authentication")
            
            # Step 1: Get authorization state
            state = await self._get_auth_state(code_challenge)
            
            # Step 2: Submit credentials and get authorization code
            auth_code = await self._submit_credentials(username, password, state)
            
            # Step 3: Exchange authorization code for tokens
            tokens = await self._exchange_code_for_tokens(auth_code, code_verifier)
            
            _LOGGER.info("Authentication successful for user: %s", username)
            return tokens
            
        except GeckoAuth0Error:
            # Re-raise specific Auth0 errors
            raise
        except aiohttp.ClientError as e:
            _LOGGER.error("Network error during authentication: %s", e)
            raise GeckoAuth0ConnectionError(f"Network error: {e}") from e
        except Exception as e:
            _LOGGER.error("Unexpected error during authentication: %s", e)
            raise GeckoAuth0Error(f"Authentication failed: {e}") from e
    
    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_token: The refresh token
            
        Returns:
            Dictionary containing new access_token and other token info
            
        Raises:
            GeckoAuth0Error: If token refresh fails
        """
        _LOGGER.debug("Refreshing access token")
        
        session = async_get_clientsession(self.hass)
        url = f"https://{self.auth0_domain}/oauth/token"

        data = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": refresh_token,
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
            "User-Agent": "Gecko/1757965853 CFNetwork/3826.600.41 Darwin/24.6.0",
        }

        # Use retry helper for transient network errors
        try:
            response_text, status = await self._post_with_retries(session, url, data=data, headers=headers)

            if status == 200:
                tokens = json.loads(response_text)
                _LOGGER.debug("Token refresh successful")
                return tokens
            elif status == 401:
                _LOGGER.warning("Refresh token expired or invalid")
                raise GeckoAuth0InvalidCredentials("Refresh token expired")
            else:
                _LOGGER.error("Token refresh failed: HTTP %s, %s", status, response_text)
                raise GeckoAuth0Error(f"Token refresh failed: HTTP {status}")

        except json.JSONDecodeError as e:
            _LOGGER.error("Failed to parse token refresh response: %s", e)
            raise GeckoAuth0Error(f"Invalid response from token refresh: {e}") from e
        except GeckoAuth0ConnectionError:
            # Re-raise connection errors
            raise
        except Exception as e:
            _LOGGER.error("Unexpected error during token refresh: %s", e)
            raise GeckoAuth0Error(f"Token refresh error: {e}") from e
    
    async def _get_auth_state(self, code_challenge: str) -> str:
        """Get the authorization page and extract the state parameter."""
        session = async_get_clientsession(self.hass)
        
        # Headers that mimic the mobile app
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-GB,en;q=0.9,en-US;q=0.8,mt;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
        }
        
        # Construct the authorization URL exactly like the mobile app
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
        _LOGGER.debug("Getting authorization state from: %s", auth_url[:100] + "...")
        
        try:
            async with session.get(auth_url, headers=headers, allow_redirects=True) as response:
                if response.status != 200:
                    raise GeckoAuth0ConnectionError(f"Failed to get authorization page: HTTP {response.status}")
                
                final_url = str(response.url)
                _LOGGER.debug("Authorization redirect URL: %s", final_url[:100] + "...")
                
                # Extract state from URL
                if "/u/login?state=" in final_url:
                    state_match = re.search(r'state=([^&]+)', final_url)
                    if state_match:
                        state = urllib.parse.unquote(state_match.group(1))
                        _LOGGER.debug("Extracted auth state successfully")
                        return state
                
                raise GeckoAuth0Error("Failed to extract state from authorization flow")
                
        except aiohttp.ClientError as e:
            _LOGGER.error("Network error getting auth state: %s", e)
            raise GeckoAuth0ConnectionError(f"Network error: {e}") from e
    
    async def _submit_credentials(self, username: str, password: str, state: str) -> str:
        """Submit credentials and get authorization code."""
        session = async_get_clientsession(self.hass)
        
        # Submit credentials directly to /u/login
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
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-user': '?1',
            'sec-fetch-dest': 'document',
            'upgrade-insecure-requests': '1',
            'cache-control': 'max-age=0'
        }
        
        _LOGGER.debug("Submitting credentials to Auth0 (password not logged)")

        # Use retry helper to tolerate transient network failures
        try:
            response_text, status, headers_out = await self._post_with_retries(
                session,
                login_url,
                params=login_params,
                data=login_data,
                headers=headers,
                allow_redirects=False,
                return_headers=True,
            )

            # Create a lightweight response-like context using returned values
            status_code = status

            if status_code == 400:
                if 'invalid' in (response_text or '').lower() or 'wrong' in (response_text or '').lower():
                    _LOGGER.warning("Invalid credentials provided")
                    raise GeckoAuth0InvalidCredentials("Invalid username or password")
                _LOGGER.error("Auth0 login failed: %s", (response_text or '')[:200])
                raise GeckoAuth0Error(f"Login failed: {(response_text or '')[:200]}")

            if status_code == 429:
                _LOGGER.warning("Rate limited by Auth0")
                raise GeckoAuth0RateLimitError("Too many authentication attempts. Please try again later.")

            if status_code in [302, 303]:
                location = headers_out.get('Location', '')
                _LOGGER.debug("Login redirect to: %s", location)

                if location.startswith('/'):
                    location = f"https://{self.auth0_domain}{location}"

                # Follow the redirect (single follow as in PoC)
                async with session.get(location, allow_redirects=False) as resume_response:
                    if resume_response.status in [302, 303]:
                        final_location = resume_response.headers.get('Location', '')
                        _LOGGER.debug("Final redirect to: %s", final_location[:100] + "...")

                        if 'code=' in final_location:
                            auth_code = self._extract_auth_code(final_location)
                            _LOGGER.debug("Authorization code extracted successfully")
                            return auth_code
                        _LOGGER.error("No authorization code in callback URL")
                        raise GeckoAuth0Error("Authentication flow failed - no authorization code received")
                    resume_text = await resume_response.text()
                    _LOGGER.error("Authorization resume failed: HTTP %s, %s", resume_response.status, resume_text[:200])
                    raise GeckoAuth0Error(f"Authorization resume failed: HTTP {resume_response.status}")

            _LOGGER.error("Unexpected login response: HTTP %s, %s", status_code, (response_text or '')[:200])
            raise GeckoAuth0Error(f"Unexpected response: HTTP {status_code}")

        except GeckoAuth0Error:
            raise
        except GeckoAuth0ConnectionError:
            raise
        except Exception as e:
            _LOGGER.error("Network error during credential submission: %s", e)
            raise GeckoAuth0ConnectionError(f"Network error: {e}") from e
    
    def _extract_auth_code(self, callback_url: str) -> str:
        """Extract authorization code from callback URL."""
        parsed = urllib.parse.urlparse(callback_url)
        params = urllib.parse.parse_qs(parsed.query)
        
        code = params.get('code', [])
        if not code:
            raise GeckoAuth0Error(f"No authorization code found in callback URL")
        
        return code[0]
    
    async def _exchange_code_for_tokens(self, auth_code: str, code_verifier: str) -> Dict[str, Any]:
        """Exchange authorization code for access tokens."""
        session = async_get_clientsession(self.hass)

        url = f"https://{self.auth0_domain}/oauth/token"

        data = {
            "client_id": self.client_id,
            "code_verifier": code_verifier,
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": self.redirect_uri,
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
            "User-Agent": "Gecko/1757965853 CFNetwork/3826.600.41 Darwin/24.6.0",
            "auth0-client": "eyJuYW1lIjoiYXV0aDAtdnVlIiwidmVyc2lvbiI6IjIuMy4xIn0=",
            "Accept-Language": "en-GB,en;q=0.5",
        }

        _LOGGER.debug("Exchanging authorization code for tokens")

        try:
            response_text, status = await self._post_with_retries(session, url, data=data, headers=headers)

            if status == 200:
                tokens = json.loads(response_text)
                _LOGGER.debug("Token exchange successful")
                return tokens
            elif status == 400:
                _LOGGER.error("Token exchange failed - invalid request: %s", response_text)
                raise GeckoAuth0Error("Token exchange failed - invalid authorization code")
            elif status == 429:
                _LOGGER.warning("Rate limited during token exchange")
                raise GeckoAuth0RateLimitError("Rate limited - please try again later")
            else:
                _LOGGER.error("Token exchange failed: HTTP %s, %s", status, response_text)
                raise GeckoAuth0Error(f"Token exchange failed: HTTP {status}")

        except json.JSONDecodeError as e:
            _LOGGER.error("Failed to parse token response: %s", e)
            raise GeckoAuth0Error(f"Invalid response from token exchange: {e}") from e
        except GeckoAuth0ConnectionError:
            raise
        except Exception as e:
            _LOGGER.error("Network error during token exchange: %s", e)
            raise GeckoAuth0ConnectionError(f"Network error: {e}") from e

    async def _post_with_retries(self, session: aiohttp.ClientSession, url: str, *, params: dict | None = None, data: dict | None = None, headers: dict | None = None, allow_redirects: bool = True, return_headers: bool = False) -> tuple[str | None, int, dict]:
        """POST helper with retries for transient network errors.

        Returns a tuple of (response_text, status, headers_dict) when return_headers=True.
        If return_headers=False, returns (response_text, status).
        Raises GeckoAuth0ConnectionError on persistent network errors.
        """
        MAX_RETRIES = 2
        BACKOFF_BASE = 0.5

        last_exc = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                async with session.post(url, params=params, data=data, headers=headers, allow_redirects=allow_redirects) as resp:
                    text = await resp.text()
                    hdrs = dict(resp.headers)
                    if return_headers:
                        return text, resp.status, hdrs
                    return text, resp.status
            except aiohttp.ClientError as e:
                last_exc = e
                _LOGGER.debug("POST attempt %s to %s failed: %s", attempt + 1, url, e)
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(BACKOFF_BASE * (2 ** attempt))
                    continue
                _LOGGER.error("POST to %s failed after retries: %s", url, last_exc)
                raise GeckoAuth0ConnectionError(f"Network error: {last_exc}") from last_exc