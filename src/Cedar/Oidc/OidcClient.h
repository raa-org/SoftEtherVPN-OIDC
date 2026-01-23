// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module

// OIDCClient.h
// Header of OIDCClient.c (OpenID Connect client API, C ABI)

#ifndef	OIDC_CLIENT_H
#define	OIDC_CLIENT_H

#include "../Cedar.h"
#include "OidcDefs.h"

// ----- Public API -----

void OidcClientSetUiBridge(const OIDC_UI_BRIDGE* bridge);

bool OidcBuildAccountKey(char* out_key, UINT out_key_size, const char* issuer_url, const char* client_id);

// Returns true if the embedded UI bridge is configured and supports purging per-account data.
bool OidcClientIsEmbeddedUiPurgeSupported(void);

// Purge embedded UI (WebView2) data for a given account_key (hex key).
OIDC_STATUS OidcClientForgetEmbeddedUiDataByKey(const char* account_key, UINT timeout_ms);

// Ensures CLIENT_AUTH has a usable OIDC IdToken.
// Returns OIDC_OK when auth->OidcIdToken is non-empty and ready for SessionConnect().
// For all non-OK statuses, the caller decides how to map it to session errors.
OIDC_STATUS ClientEnsureOidcIdToken(CLIENT_AUTH* auth);

// Interactive sign-in (opens browser/WebView on supported platforms)
OIDC_STATUS OidcClientInteractiveSignIn(CLIENT_AUTH* auth, const OIDC_CONFIG* oidc_cfg, OIDC_TOKENS* out_tokens  /* non-NULL */);

// Refresh by refresh_token
OIDC_STATUS OidcClientTrySilentRefreshWithStoredToken(char* username, const OIDC_CONFIG* cfg, OIDC_TOKENS* out_tokens /* non-NULL */);

// Service-side helper: store refresh token for this user/config.
OIDC_STATUS OidcClientStoreRefreshForUser(const char* username, const OIDC_CONFIG* oidc_cfg, const char* refresh_token, UINT64 expires_at_ms);

OIDC_STATUS OidcClientHasStoredRefreshForUser(char* username, const OIDC_CONFIG* oidc_cfg, bool* out_has /* non-NULL */);

OIDC_STATUS OidcClientClearRefreshForUser(const char* username, const OIDC_CONFIG* oidc_cfg);

bool OidcClientFillAuthFromIdToken(CLIENT_AUTH* auth, const char* id_token);

void OidcClientFreeTokens(OIDC_TOKENS* oidc_tokens);

// Human-readable error string (static; do not free)
const char* OidcClientErrorToStr(OIDC_STATUS e);

#endif	// OIDC_CLIENT_H
