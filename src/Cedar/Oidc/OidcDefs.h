#ifndef OIDC_DEFS_H
#define OIDC_DEFS_H

#include "../Cedar.h"

#define OIDC_UI_PURGE_DEFAULT_TIMEOUT_MS 15000u
#define OIDC_ACCOUNT_KEY_SHA256_HEX_LEN 64
#define OIDC_ACCOUNT_KEY_SHA256_HEX_BUF_SIZE (OIDC_ACCOUNT_KEY_SHA256_HEX_LEN + 1)

// Error codes
typedef enum OIDC_STATUS
{
	OIDC_OK = 0,
	OIDC_ERR_NOT_SUPPORTED,
	OIDC_ERR_NOT_IMPLEMENTED,
	OIDC_ERR_TIMEOUT,
	OIDC_ERR_NETWORK,
	OIDC_ERR_USER_CANCELED,
	OIDC_ERR_INVALID_PARAM,
	OIDC_ERR_PROVIDER,
	OIDC_ERR_INVALID_TOKEN,
	OIDC_ERR_STORAGE_NOT_FOUND,
	OIDC_ERR_INTERNAL,
} OIDC_STATUS;

typedef struct OIDC_CONFIG {
	char IssuerUrl[256];	// e.g. "https://idp.example.com/realms/foo"
	char ClientId[128];		// public client id
	char RedirectUri[256];	// e.g. "http://127.0.0.1:38955/callback"
	char Scopes[256];		// e.g. "openid profile offline_access"
	bool UsePkceS256;		// true to use S256 (recommended)
} OIDC_CONFIG;

// Tokens (pointers owned by client; copy if you need to persist)
typedef struct OIDC_TOKENS
{
	char* AccessToken;					// may be NULL
	UINT64 AccessTokenExpiresAt;		// epoch milliseconds
	char* IdToken;						// may be NULL
	char* RefreshToken;					// may be NULL
	UINT64 RefreshTokenExpiresAt;		// epoch milliseconds
} OIDC_TOKENS;

typedef struct OIDC_UI_BRIDGE
{
	// Opaque pointer passed to all callbacks (may be NULL).
	void* UserData;

	// Open an interactive UI and navigate to the given URL.
	// account_key is a stable per-account identifier used to select an isolated UI/profile storage.
	// Returns true on success.
	bool (*Open)(const char* url, const char* account_key, void* user_data);

	// Poll whether the UI has been closed.
	// timeout_ms == 0 means non-blocking poll.
	// Returns true if closed, false if still open.
	bool (*WaitClosed)(UINT timeout_ms, void* user_data);

	// Called once when the flow ends; should close UI and release resources.
	// Returns true on success (best-effort).
	bool (*Close)(void* user_data);

	// Purge of per-account UI/profile data used by embedded flows.
	// Returns true on success.
	bool (*PurgeAccountData)(const char* account_key, UINT timeout_ms, void* user_data);

} OIDC_UI_BRIDGE;

#endif
