#ifndef OIDC_HTTP_H
#define OIDC_HTTP_H

#include "Mayaqua/Mayaqua.h"
#include "OidcDefs.h"   // for OIDC_STATUS

#ifdef __cplusplus
extern "C" {
#endif

    /* Parse http(s) URL; sets use_tls=true for https, false for http. */
    OIDC_STATUS OidcHttpParseUrl( const char* url, bool* use_tls, char* host, size_t host_sz, UINT* port, char* path, size_t path_sz);

    /* GET url over HTTP/HTTPS. Allocates *out_body via ZeroMalloc; caller must Free(). */
    OIDC_STATUS OidcHttpsGet(const char* url, char** out_body, UINT timeout_ms);

    /* POST application/x-www-form-urlencoded to host/port/path over HTTP or HTTPS.
       Allocates *out_body via ZeroMalloc; caller must Free().
       Returns 1 on success, 0 on failure. */
    OIDC_STATUS OidcHttpsPostForm(const char* host, UINT port, const char* path, const char* form_body, char** out_body, UINT timeout_ms, bool use_tls);

#ifdef __cplusplus
}
#endif

#endif /* OIDC_HTTP_H */