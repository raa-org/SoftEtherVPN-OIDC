// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
//
// OidcLoopback.c
// Local HTTP loopback listener for OIDC redirects (cross-platform via Mayaqua Network.*)

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"   // Zero
#include "Mayaqua/Str.h"      // StrCmpi, IsEmptyStr
#include "Mayaqua/Network.h"
#include "OidcLoopback.h"
#include "OidcUrlEncoding.h"

#include <string.h>
#include <stdio.h>

struct OIDC_LOOPBACK
{
    SOCK* ListenSock;
    UINT  Port;
    char  Path[256];
};

/* Local case-insensitive strncmp, returns 0 when equal */
static int StrnCmpiLocal(const char* a, const char* b, size_t n)
{
    size_t i;

    if (a == NULL || b == NULL)
    {
        return -1;
    }

    for (i = 0; i < n; i++)
    {
        char ca = ToLower(a[i]);
        char cb = ToLower(b[i]);

        if (ca != cb)
        {
            return (int)((unsigned char)ca) - (int)((unsigned char)cb);
        }

        if (ca == '\0')
        {
            break;
        }
    }

    return 0;
}

/* Parse redirect_uri like \"http://127.0.0.1:38955/callback\".
   Extract host, port, path. Returns 1 on success. */
static int OidcParseRedirect(const char* uri, char* host, size_t host_sz, UINT* port, char* path, size_t path_sz)
{
    int ok = 0;
    const char* p;
    const char* h;
    const char* colon;
    const char* slash;

    if (host == NULL || host_sz == 0 || port == NULL || path == NULL || path_sz == 0)
    {
        return 0;
    }

    host[0] = 0;
    path[0] = 0;
    *port = 0;

    if (uri == NULL)
    {
        return 0;
    }

    if (StrnCmpiLocal(uri, "http://", 7) != 0)
    {
        return 0;
    }

    p = uri + 7;

    h = p;

    colon = strchr(p, ':');
    slash = strchr(p, '/');

    if (slash == NULL)
    {
        return 0;
    }

    if (colon != NULL && colon < slash)
    {
        UINT len = (UINT)(colon - h);
        if (len >= host_sz)
        {
            return 0;
        }
        Copy(host, h, len);
        host[len] = 0;

        *port = ToInt((char*)(colon + 1));
    }
    else
    {
        UINT len = (UINT)(slash - h);
        if (len >= host_sz)
        {
            return 0;
        }
        Copy(host, h, len);
        host[len] = 0;

        *port = 80;
    }

    if (*port == 0)
    {
        return 0;
    }

    if (StrLen((char*)slash) >= path_sz)
    {
        return 0;
    }

    StrCpy(path, path_sz, (char*)slash);

    ok = 1;

    return ok;
}

/* Very small query string parser: ?key=value&key2=value2 ... */
static const char* OidcQueryFind(const char* query, const char* key, char* out, size_t outsz)
{
    const char* p;
    size_t keylen;

    if (out && outsz > 0)
    {
        out[0] = 0;
    }

    if (query == NULL || key == NULL || out == NULL || outsz == 0)
    {
        return NULL;
    }

    keylen = StrLen((char*)key);

    p = query;

    while (*p != 0)
    {
        const char* k = p;
        const char* eq = strchr(k, '=');
        const char* amp = strchr(k, '&');

        if (eq == NULL && amp == NULL)
        {
            if (StrLen((char*)k) == keylen && StrnCmpiLocal(k, key, keylen) == 0)
            {
                out[0] = 0;
                return out;
            }
            break;
        }

        if (amp != NULL && (eq == NULL || amp < eq))
        {
            if ((UINT)(amp - k) == keylen && StrnCmpiLocal(k, key, keylen) == 0)
            {
                out[0] = 0;
                return out;
            }
            p = amp;
            p++;
            continue;
        }

        if (eq != NULL)
        {
            if ((UINT)(eq - k) == keylen && StrnCmpiLocal(k, key, keylen) == 0)
            {
                const char* v = eq;
                const char* end = amp ? amp : (k + StrLen((char*)k));
                UINT vlen;
                char tmp[1024];

                v++;
                vlen = (UINT)(end - v);

                if (vlen >= sizeof(tmp))
                {
                    vlen = sizeof(tmp);
                    vlen--;
                }

                Copy(tmp, v, vlen);
                tmp[vlen] = 0;

                if (OidcUrlDecode(tmp, out, outsz))
                {
                    return out;
                }
                else
                {
                    return NULL;
                }
            }

            if (amp == NULL)
            {
                break;
            }

            p = amp;
            p++;
            continue;
        }

        break;
    }

    return NULL;
}


/* Build and send a minimal HTTP response page */
static void OidcSendHttpResponse(SOCK* s, bool ok)
{
    static const char* kOkBody =
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>OK</title></head>"
        "<body>Login completed. You can close this window.</body></html>";

    static const char* kErrBody =
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Error</title></head>"
        "<body>Login failed.</body></html>";

    char hdr[512];
    const char* body;
    UINT body_len;

    body = ok ? kOkBody : kErrBody;
    body_len = (UINT)StrLen(body);

    Format(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n"
        "\r\n",
        ok ? "200 OK" : "400 Bad Request",
        body_len);

    SendAll(s, (void*)hdr, (UINT)StrLen(hdr), false);
    SendAll(s, (void*)body, body_len, false);
}

/* Read request line and headers until blank line; return request-target path+query into out_path */
static int OidcHttpReadRequestTarget(SOCK* s, char* out_path, size_t outsz)
{
    int ok = 0;
    char* line;

    if (out_path == NULL || outsz == 0)
    {
        return 0;
    }

    out_path[0] = 0;

    line = RecvLine(s, 8192);
    if (line == NULL)
    {
        return 0;
    }

    if (StrnCmpiLocal(line, "GET ", 4) == 0)
    {
        const char* p = line + 4;
        const char* sp = strchr(p, ' ');
        if (sp != NULL)
        {
            UINT len = (UINT)(sp - p);
            if (len + 1 < outsz)
            {
                Copy(out_path, p, len);
                out_path[len] = 0;
                ok = 1;
            }
        }
    }

    Free(line);

    if (ok == 0)
    {
        return 0;
    }

    while (true)
    {
        line = RecvLine(s, 8192);
        if (line == NULL)
        {
            break;
        }

        if (line[0] == 0)
        {
            Free(line);
            break;
        }

        Free(line);
    }

    return 1;
}

int OidcLoopbackStart(OIDC_LOOPBACK** out_lb, const char* redirect_uri)
{
    OIDC_LOOPBACK* lb;
    char host[256];
    char path[256];
    UINT port;
    IP ip;
    SOCK* ls;
    int ok;

    if (out_lb == NULL || redirect_uri == NULL)
    {
        return 0;
    }

    *out_lb = NULL;

    host[0] = 0;
    path[0] = 0;
    port = 0;

    ok = OidcParseRedirect(redirect_uri, host, sizeof(host), &port, path, sizeof(path));
    if (ok == 0)
    {
        return 0;
    }

    if (StrCmpi(host, "127.0.0.1") != 0 && StrCmpi(host, "localhost") != 0)
    {
        return 0;
    }

    SetIP(&ip, 127, 0, 0, 1);

    ls = ListenEx2(port, true, false, &ip);
    if (ls == NULL)
    {
        return 0;
    }

    lb = (OIDC_LOOPBACK*)ZeroMalloc(sizeof(OIDC_LOOPBACK));
    if (lb == NULL)
    {
        ReleaseSock(ls);
        return 0;
    }

    lb->ListenSock = ls;
    lb->Port = port;
    StrCpy(lb->Path, sizeof(lb->Path), path);

    *out_lb = lb;

    return 1;
}

int OidcLoopbackWait(OIDC_LOOPBACK* lb, char* out_code, size_t code_sz, char* out_state, size_t state_sz)
{
    SOCK* s;
    char target[2048];
    char* qmark;
    char path_only[512];
    char query[1536];
    char code[1024];
    char state[512];
    int ok;

    if (lb == NULL || out_code == NULL || code_sz == 0 || out_state == NULL || state_sz == 0)
    {
        return 0;
    }

    out_code[0] = 0;
    out_state[0] = 0;

    s = Accept(lb->ListenSock);
    if (s == NULL)
    {
        return 0;
    }

    SetTimeout(s, 10000);

    target[0] = 0;

    ok = OidcHttpReadRequestTarget(s, target, sizeof(target));
    if (ok == 0)
    {
        OidcSendHttpResponse(s, false);
        ReleaseSock(s);
        return 0;
    }

    qmark = strchr(target, '?');
    if (qmark != NULL)
    {
        UINT plen = (UINT)(qmark - target);
        if (plen >= sizeof(path_only))
        {
            plen = sizeof(path_only) - 1;
        }
        Copy(path_only, target, plen);
        path_only[plen] = 0;

        StrCpy(query, sizeof(query), qmark + 1);
    }
    else
    {
        StrCpy(path_only, sizeof(path_only), target);
        query[0] = 0;
    }

    if (StrCmpi(path_only, lb->Path) != 0)
    {
        OidcSendHttpResponse(s, false);
        ReleaseSock(s);
        return 0;
    }

    code[0] = 0;
    state[0] = 0;

    if (OidcQueryFind(query, "code", code, sizeof(code)) == NULL)
    {
        OidcSendHttpResponse(s, false);
        ReleaseSock(s);
        return 0;
    }

    OidcQueryFind(query, "state", state, sizeof(state));

    StrCpy(out_code, code_sz, code);
    StrCpy(out_state, state_sz, state);

    OidcSendHttpResponse(s, true);

    ReleaseSock(s);

    return 1;
}

void OidcLoopbackCancel(OIDC_LOOPBACK* lb)
{
    if (lb != NULL && lb->ListenSock != NULL)
    {
        ReleaseSock(lb->ListenSock);
        lb->ListenSock = NULL;
    }
}

void OidcLoopbackStop(OIDC_LOOPBACK* lb)
{
    if (lb != NULL)
    {
        OidcLoopbackCancel(lb);
        Free(lb);
    }
}
