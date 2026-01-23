// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
//
// OidcLoopback.h
// Local HTTP loopback listener for OIDC redirects (uses Mayaqua Network.*)

#ifndef OIDC_LOOPBACK_H
#define OIDC_LOOPBACK_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct OIDC_LOOPBACK OIDC_LOOPBACK;

	/* Start listener bound to host:port from redirect_uri.
	   Only http://127.0.0.1:<port>/path or http://localhost:<port>/path are accepted.
	   Returns 1 on success, 0 on failure. */
	int OidcLoopbackStart(OIDC_LOOPBACK** out_lb, const char* redirect_uri);

	/* Wait for single GET callback and extract ?code= and ?state=.
	   Blocks until a request arrives. For MVP no timeout; add cancellation later.
	   Returns 1 on success, 0 on failure. */
	int OidcLoopbackWait(OIDC_LOOPBACK* lb, char* out_code, size_t code_sz, char* out_state, size_t state_sz);

	/* Non-blocking cancellation signal for a running OidcLoopbackWait(...). */
	void OidcLoopbackCancel(OIDC_LOOPBACK* lb);

	/* Stop and free resources. Safe to call with NULL. */
	void OidcLoopbackStop(OIDC_LOOPBACK* lb);

#ifdef __cplusplus
}
#endif

#endif /* OIDC_LOOPBACK_H */
