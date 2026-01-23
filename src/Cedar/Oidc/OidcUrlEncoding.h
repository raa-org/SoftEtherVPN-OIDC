// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
//
// OidcUrlEncoding.h
// URL percent-encoding/decoding (RFC 3986) for OIDC query/form params.

#ifndef OIDC_URL_ENCODING_H
#define OIDC_URL_ENCODING_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

	/* Percent-encode per RFC 3986.
	   Leaves unreserved [A-Z a-z 0-9 - _ . ~] as-is.
	   Writes NUL-terminated string to out.
	   Returns 1 on success, 0 on failure. */
	int OidcUrlEncode(const char* s, char* out, size_t outsz);

	/* Percent-decode.
	   For query components, treats '+' as space.
	   Writes NUL-terminated string to out.
	   Returns 1 on success, 0 on failure. */
	int OidcUrlDecode(const char* s, char* out, size_t outsz);

#ifdef __cplusplus
}
#endif

#endif /* OIDC_URL_ENCODING_H */
