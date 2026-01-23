// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
//
// OidcSecureStoreWin32.c
// Non-Windows placeholder implementations.
// Non-Windows: Secure per-user refresh-token storage.
// These return NOT_IMPLEMENTED so the codebase compiles on Unix builds.
// A real Unix implementation should use a platform keyring (e.g., macOS Keychain,
// libsecret/gnome-keyring, kwallet, or an encrypted file with OS-protected keys).

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Encrypt.h"   // Sha2_256
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Crypto/Key.h"

#include "OidcSecureStore.h"

OIDC_STATUS OidcStoreRefreshSave(const OIDC_CONFIG* cfg, const char* subject, const char* refresh_token, UINT64 expires_at_ms)
{
	(void)cfg; (void)subject; (void)refresh_token; (void)expires_at_ms;
	return OIDC_ERR_NOT_IMPLEMENTED;
}

OIDC_STATUS OidcStoreRefreshLoad(const OIDC_CONFIG* cfg, const char* subject, char** out_refresh_token, UINT64* out_expires_at_ms)
{
	if (out_refresh_token != NULL) *out_refresh_token = NULL;
	if (out_expires_at_ms != NULL) *out_expires_at_ms = 0;
	(void)cfg; (void)subject;
	return OIDC_ERR_NOT_IMPLEMENTED;
}

OIDC_STATUS OidcStoreRefreshClear(const OIDC_CONFIG* cfg, const char* subject)
{
	(void)cfg; (void)subject;
	return OIDC_ERR_NOT_IMPLEMENTED;
}
