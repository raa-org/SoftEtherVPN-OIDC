// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
//
// OidcSecureStore.h
// Secure per-user refresh-token storage.

#ifndef OIDC_SECURE_STORE_H
#define OIDC_SECURE_STORE_H

#include "Mayaqua/Mayaqua.h"
#include "OidcDefs.h"      // OIDC_STATUS, OIDC_CONFIG (issuer, client_id, redirect_uri)

#ifdef __cplusplus
extern "C" {
#endif

    /* Save refresh token (replaces existing entry).
       subject can be NULL if unknown; expires_at_ms may be 0 if unknown. */
    OIDC_STATUS OidcStoreRefreshSave(const OIDC_CONFIG* cfg, const char* subject, const char* refresh_token, UINT64 expires_at_ms);

    /* Load refresh token. Caller must Free() *out_refresh_token.
       Returns OIDC_ERR_NOT_FOUND if missing. */
    OIDC_STATUS OidcStoreRefreshLoad(const OIDC_CONFIG* cfg, const char* subject, char** out_refresh_token, UINT64* out_expires_at_ms);

    /* Delete stored refresh token (best-effort). */
    OIDC_STATUS OidcStoreRefreshClear(const OIDC_CONFIG* cfg, const char* subject);

#ifdef __cplusplus
}
#endif

#endif /* OIDC_SECURE_STORE_H */
