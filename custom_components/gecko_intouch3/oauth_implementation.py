"""Shared PKCE behavior for built-in and user-supplied Gecko OAuth clients."""

from homeassistant.helpers import config_entry_oauth2_flow

from .const import API_BASE_URL


class GeckoPKCEOAuth2Implementation(
    config_entry_oauth2_flow.LocalOAuth2ImplementationWithPkce
):
    """Gecko OAuth2 implementation with PKCE and optional client secret."""

    @property
    def extra_authorize_data(self) -> dict:
        """Extra data for the authorize URL."""
        data = (
            super().extra_authorize_data
        )  # This includes code_challenge and code_challenge_method
        data.update(
            {
                # offline_access is REQUIRED to receive a refresh_token from Auth0
                # Without it, only an access_token is returned which expires and cannot be renewed
                "scope": "openid profile email offline_access",
                "audience": API_BASE_URL,
            }
        )
        return data
