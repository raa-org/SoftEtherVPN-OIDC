// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
//
// OidcPkce.h
// PKCE utilities and base64url helpers.

#ifndef OIDC_PKCE_H
#define OIDC_PKCE_H

#include <stddef.h>
#include "OidcDefs.h"  // for OIDC_STATUS

#ifdef __cplusplus
extern "C" {
#endif

#define OIDC_PKCE_VERIFIER_MAX 128
#define OIDC_PKCE_BUF          192

	int OidcRandBytes(unsigned char* dst, size_t len);
	int OidcSha256(const void* data, size_t len, unsigned char out32[32]);
	int OidcEncodeBase64UrlNoPad(const unsigned char* in, size_t inlen, char* out, size_t outsz);

	/* Generates code_verifier (43..128) and code_challenge=S256(base64url no-pad). */
	OIDC_STATUS OidcGeneratePkce(char* out_verifier, size_t verifier_sz, char* out_challenge, size_t challenge_sz);

#ifdef __cplusplus
}
#endif

#endif /* OIDC_PKCE_H */