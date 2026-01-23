#ifndef OIDC_CLIENT_CORE_H
#define OIDC_CLIENT_CORE_H

#include "Mayaqua/Mayaqua.h"
#include "OidcDefs.h"          // OIDC_STATUS, OIDC_TOKENS, OIDC_CONFIG
#include "OidcUrlEncoding.h"   // OidcUrlEncode

#ifdef __cplusplus
extern "C" {
#endif

    /* Build {issuer}/protocol/openid-connect/auth (Keycloak) or /authorize (generic). */
    OIDC_STATUS OidcBuildAuthorizeEndpoint(const char* issuer, char* out, size_t outsz);

    /* Build {issuer}/protocol/openid-connect/token (Keycloak) or /token (generic). */
    OIDC_STATUS OidcBuildTokenEndpoint(const char* issuer, char* out, size_t outsz);

    /* Compose full authorize URL with required query params.
       - Uses cfg->IssuerUrl / ClientId / RedirectUri / Scopes (fallback "openid")
       - Adds response_type=code, code_challenge_method=S256, PKCE code_challenge,
         state and nonce provided by caller (already generated).
       Returns 1 on success. */
    OIDC_STATUS OidcComposeAuthorizeUrl( const OIDC_CONFIG* cfg, const char* code_challenge, const char* state, const char* nonce, char* out_url, size_t out_url_sz);

    /* Exchange authorization code for ID token, refresh token over HTTPS (application/x-www-form-urlencoded).
       - Fills out_tokens->IdToken, out_tokens->RefreshToken, out_tokens->RefreshExpiresAt on success.
       - out_tokens->AccessToken stays NULL.
       - out_tokens->ExpiresAt is set to 0 (client doesn't track expiry).
       No client-side JWT validation is performed.
       Returns OIDC_OK on success. */
    OIDC_STATUS OidcExchangeAuthCodeForTokens( const OIDC_CONFIG* cfg, const char* code, const char* code_verifier, OIDC_TOKENS* out_tokens, UINT timeout_ms);

    /* Exchange refresh_token for new tokens. */
    OIDC_STATUS OidcExchangeRefreshForTokens(const OIDC_CONFIG* cfg, const char* refresh_token,  OIDC_TOKENS* out_tokens, UINT timeout_ms);



#ifdef __cplusplus
}
#endif

#endif /* OIDC_CLIENT_CORE_H */
