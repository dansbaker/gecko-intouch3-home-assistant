"""Gecko OAuth application credentials managed by Home Assistant."""

from homeassistant.components.application_credentials import ClientCredential
from homeassistant.core import HomeAssistant
from homeassistant.helpers.config_entry_oauth2_flow import AbstractOAuth2Implementation

from .const import OAUTH2_AUTHORIZE, OAUTH2_TOKEN
from .oauth_implementation import GeckoPKCEOAuth2Implementation


class GeckoApplicationCredentialsImplementation(GeckoPKCEOAuth2Implementation):
    """PKCE implementation retaining HA's credential identity and display name."""

    def __init__(
        self, hass: HomeAssistant, auth_domain: str, credential: ClientCredential
    ) -> None:
        super().__init__(
            hass,
            auth_domain,
            client_id=credential.client_id,
            client_secret=credential.client_secret,
            authorize_url=OAUTH2_AUTHORIZE,
            token_url=OAUTH2_TOKEN,
        )
        self._credential_name = credential.name or credential.client_id

    @property
    def name(self) -> str:
        """Show which registered application the user is choosing."""
        return self._credential_name


async def async_get_auth_implementation(
    hass: HomeAssistant, auth_domain: str, credential: ClientCredential
) -> AbstractOAuth2Implementation:
    """Let HA supply application credentials while Gecko requires PKCE."""
    return GeckoApplicationCredentialsImplementation(hass, auth_domain, credential)
