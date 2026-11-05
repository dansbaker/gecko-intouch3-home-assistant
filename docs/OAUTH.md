# Gecko OAuth application credentials

The custom integration now supports Home Assistant's **Application credentials**
settings in addition to its existing bundled Gecko login. HA stores the application
credentials and manages access-token renewal. Both routes use PKCE, the Gecko API
audience, and the existing login scopes including `offline_access`.

## Existing installations

Existing entries continue using their stored `auth_implementation`; adding another
application does not silently replace that provider or change the account. The
bundled `gecko` provider remains available for the custom integration. This is a
compatibility measure, not the proposed final authentication design for core.

## Using credentials issued for your application

This route is available when Gecko has supplied or approved an OAuth application
for your use. A spa account login/password is not an OAuth application credential.
No self-service credential-issuance route is assumed or implemented here.

1. Obtain the authorized client ID and, for a confidential application, its client
   secret from Gecko. Public PKCE applications can use an empty secret when the
   provider permits it.
2. Confirm the application is allowed to access the Gecko API and has Home
   Assistant's callback registered. With the **My** integration enabled, HA uses
   `https://my.home-assistant.io/redirect/oauth`.
3. Add the credentials for **Gecko** in Home Assistant's Application credentials
   settings. Give the entry a recognizable name.
4. Start Gecko setup and choose that named application when HA presents the OAuth
   implementation picker. Sign in with the intended Gecko spa account.

The credentials remain in HA's managed credential storage. Gecko config entries
record the selected provider identity and user tokens, not a copied client secret.
The account's stable unique ID prevents adding the same account again under a
second OAuth application. To change providers for an existing account, use the
reauthentication flow and sign in to the same Gecko account; vessel data remains
intact. Do not delete a configured integration merely to change credentials.

## Behavior and verification

The implementation accepts both public and confidential clients. The authorization
URL contains the client ID and S256 challenge, not the client secret or verifier.
Code exchange uses the same verifier and callback URI. Refresh uses the selected
client credentials, and HA preserves a refresh token omitted by the provider.
Invalid credentials require reauthentication; transient HTTP 429/503 refresh
failures do not start a login loop.

Tests cover the real HA credential storage/provider lookup and flow manager, and
mock HTTP at token exchange/refresh boundaries to check request fields and state
preservation. `application_credentials.py` and `oauth_implementation.py` have full
measured line coverage. This is not proof that Gecko will issue credentials or
approve the requested API/callback permissions. Live OAuth deployment validation
remains required before core submission.

Official integration guidance: [OAuth and application credentials](https://contributors.home-assistant.io/core/integrations/oauth2/).
