// ======================================================================
// OidcServer.h - SoftEtherVPN (Cedar) - OIDC / JWT validation
// ======================================================================

#ifndef CEDAR_OIDC_SERVER_H
#define CEDAR_OIDC_SERVER_H

#include "../Cedar.h"   // brings in Mayaqua headers and SoftEther basics

// ---- Tunables (safe, conservative) -----------------------------------
#define OIDC_MAX_ISS_LEN              511
#define OIDC_MAX_AUD_LEN              255
#define OIDC_MAX_KID_LEN              127
#define OIDC_MAX_SUB_LEN              255
#define OIDC_MAX_USERNAME_LEN         255
#define OIDC_MAX_PUBKEY_PEM_LEN       4096
#define OIDC_MAX_CLAIM_NAME_LEN       127

// ---- Server-side OIDC configuration -------------
typedef struct OIDC_SERVER_CONFIG
{
	// Test toggle: if true, accept syntactically valid JWTs without cryptographic verification.
	// We still require "looks-like-JWT" (two dots) unless AllowAnyStringForTest is also set.
	bool EnableTestMode;

	// Extra permissive test mode: accept *any* non-empty string (used for local, offline demos).
	bool AllowAnyStringForTest;

	// Optional static PEM-encoded public key (RSA or EC) to validate RS256/ES256 ID tokens.
	// If empty and EnableTestMode == false, the validator will try JWKS-based resolution.
	char StaticPublicKeyPem[OIDC_MAX_PUBKEY_PEM_LEN + 1];

	// Optional expected KID (header). If set, require kid to match.
	char ExpectedKid[OIDC_MAX_KID_LEN + 1];

	// Optional issuer / audience checks.
	char ExpectedIssuer[OIDC_MAX_ISS_LEN + 1];
	char ExpectedAudience[OIDC_MAX_AUD_LEN + 1];

	// Claim name to map to SoftEther username.
	char UsernameClaim[OIDC_MAX_CLAIM_NAME_LEN + 1];

	// Basic clock skew (seconds) when checking exp/nbf.
	UINT ClockSkewSec;
} OIDC_SERVER_CONFIG;

// ---- Validation result (a few common fields for logging/auditing) ----
typedef struct OIDC_VALIDATION_RESULT
{
	bool SignatureOk;
	bool ExpOk;
	bool NbfOk;
	bool IssOk;
	bool AudOk;

	UINT Alg; // libjwt alg as UINT, 0 if unknown

	UINT64 Exp; // UNIX seconds, 0 if missing
	UINT64 Nbf; // UNIX seconds, 0 if missing
	UINT64 Iat; // UNIX seconds, 0 if missing

	char Kid[OIDC_MAX_KID_LEN + 1];
	char Iss[OIDC_MAX_ISS_LEN + 1];
	char Aud[OIDC_MAX_AUD_LEN + 1];
	char Sub[OIDC_MAX_SUB_LEN + 1];
	char PreferredUsername[OIDC_MAX_USERNAME_LEN + 1];
	char Username[OIDC_MAX_USERNAME_LEN + 1];
} OIDC_VALIDATION_RESULT;

// ---- API --------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

// Quick heuristic: does the string look like a JWT ("x.y.z")?
bool OidcIsProbablyJwt(const char *s);

// Main validator.
// Returns true on accept (test-mode or verified), false on reject.
// - id_token: OIDC ID token to validate
// - cfg: test-mode toggle and/or static PEM key
// - out: optional result struct (zeroed and filled if non-NULL)
// - err: optional human-readable reason (for logs), may be NULL
// - err_size: size of err buffer (ignored if err == NULL)
bool OidcValidateIdToken(const char *id_token,
                         const OIDC_SERVER_CONFIG *cfg,
                         OIDC_VALIDATION_RESULT *out,
                         char *err,
                         UINT err_size);

#ifdef __cplusplus
}
#endif

#endif // CEDAR_OIDC_SERVER_H
