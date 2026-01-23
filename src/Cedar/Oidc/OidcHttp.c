// OidcHttp.c - HTTPS POST helper built on Mayaqua HTTP/Network

#include "OidcHttp.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/HTTP.h"

/* Build Host header. Append :port only when non-default for scheme. */
static void BuildHostHeader(const char* host, UINT port, bool use_tls, char* out_host_header, UINT out_host_header_sz)
{
    UINT default_port = use_tls ? 443u : 80u;

    StrCpy(out_host_header, out_host_header_sz, (char*)host);

    if (port != 0 && port != default_port)
    {
        char tmp[16];
        Format(tmp, sizeof(tmp), ":%u", port);
        StrCat(out_host_header, out_host_header_sz, tmp);
    }
}

// Read HTTP body according to headers: chunked, content-length, or until close.
static int OidcReadHttpBody(SOCK* socket, HTTP_HEADER* http_header, char** out_body)
{
    int res = 0;

    if (out_body) { *out_body = NULL; }

    if (socket != NULL && http_header != NULL && out_body != NULL)
    {
        HTTP_VALUE* te = GetHttpValue(http_header, "Transfer-Encoding");
        if (te != NULL && InStr(te->Data, "chunked"))
        {
            BUF* out = NewBuf();
            if (out != NULL)
            {
                while (true)
                {
                    char* line = RecvLine(socket, HTTP_HEADER_LINE_MAX_SIZE);
                    UINT chunk_size = 0;

                    if (line == NULL)
                    {
                        break;
                    }

                    Trim(line);
                    chunk_size = HexToInt(line);
                    Free(line);

                    if (chunk_size == 0)
                    {
                        // trailers (optional) until blank line
                        while (true)
                        {
                            char* tr = RecvLine(socket, HTTP_HEADER_LINE_MAX_SIZE);
                            if (tr == NULL) { break; }
                            if (IsEmptyStr(tr)) { Free(tr); break; }
                            Free(tr);
                        }
                        res = 1;
                        break;
                    }

                    {
                        char* buf = (char*)ZeroMalloc(chunk_size);
                        UINT got = 0;

                        if (buf == NULL)
                        {
                            break;
                        }

                        while (got < chunk_size)
                        {
                            UINT n = Recv(socket, buf + got, chunk_size - got, true);
                            if (n == 0)
                            {
                                break;
                            }
                            got += n;
                        }

                        if (got != chunk_size)
                        {
                            Free(buf);
                            break;
                        }

                        WriteBuf(out, buf, got);
                        Free(buf);

                        // consume CRLF after chunk data
                        {
                            char crlf[2];
                            UINT n = Recv(socket, crlf, 2, true);
                            if (n != 2)
                            {
                                break;
                            }
                        }
                    }
                }

                if (res)
                {
                    // finalize buffer
                    WriteBuf(out, "", 1);
                    *out_body = (char*)out->Buf;
                    out->Buf = NULL;
                }

                FreeBuf(out);
            }
        }
        else
        {
            bool secure = socket->SecureMode;

            UINT content_len = GetContentLength(http_header);
            if (content_len > 0)
            {
                char* buf = (char*)ZeroMalloc(content_len + 1);
                if (buf != NULL)
                {
                    UINT got = 0;
                    while (got < content_len)
                    {
                        UINT n = Recv(socket, buf + got, content_len - got, secure);
                        if (n == 0)
                        {
                            Debug("Recv body: early EOF or timeout, got=%u of %u\n", got, content_len);
                            break;
                        }
                        got += n;
                    }

                    if (got == content_len)
                    {
                        buf[content_len] = 0;
                        *out_body = buf;
                        res = 1;
                    }
                    else
                    {
                        Free(buf);
                    }
                }
            }
            else
            {
                // No length and no chunked -> read until connection close
                const UINT MAX_BODY = 2 * 1024 * 1024; // 2 MB safety cap
                BUF* out = NewBuf();
                if (out != NULL)
                {
                    char tmp[4096];
                    UINT total = 0;

                    while (true)
                    {
                        UINT n = Recv(socket, tmp, sizeof(tmp), secure);
                        if (n == 0)
                        {
                            // closed or timeout -> end of body
                            break;
                        }

                        total += n;
                        if (total > MAX_BODY)
                        {
                            // too large -> abort
                            FreeBuf(out);
                            out = NULL;
                            break;
                        }

                        WriteBuf(out, tmp, n);
                    }

                    if (out != NULL)
                    {
                        // NUL-terminate for convenience
                        WriteBuf(out, "", 1);

                        *out_body = (char*)out->Buf; // transfer ownership
                        out->Buf = NULL;
                        res = 1;

                        FreeBuf(out);
                    }
                }
}
        }
    }

    return res;
}

// Parse http(s) URL -> scheme (TLS or not), host, port, path.
// Returns OIDC_OK on success, OIDC_ERR_INTERNAL on failure.
OIDC_STATUS OidcHttpParseUrl( const char* url, bool* use_tls, char* host, size_t host_sz, UINT* port, char* path, size_t path_sz)
{
    OIDC_STATUS res = OIDC_ERR_INTERNAL;

    // Initialize outputs
    if (use_tls) *use_tls = false;
    if (host && host_sz) host[0] = 0;
    if (port) *port = 0;
    if (path && path_sz) path[0] = 0;

    if (IsEmptyStr((char*)url) == false &&
        use_tls != NULL &&
        host != NULL && host_sz > 0 &&
        port != NULL &&
        path != NULL && path_sz > 0)
    {
        const char* p = NULL;

        // Detect scheme and default port
        if (StartWith((char*)url, "https://"))
        {
            p = url + 8;
            *use_tls = true;
            *port = 443;
        }
        else if (StartWith((char*)url, "http://"))
        {
            p = url + 7;
            *use_tls = false;
            *port = 80;
        }

        if (p != NULL)
        {
            const char* h_start = p;
            const char* after_host = NULL;

            // Handle [IPv6-literal]
            if (*p == '[')
            {
                const char* rb = strchr(p, ']');
                if (rb != NULL)
                {
                    UINT hlen = (UINT)(rb - (p + 1));
                    if (hlen > 0 && hlen < host_sz)
                    {
                        Copy(host, p + 1, hlen);
                        host[hlen] = 0;
                        after_host = rb + 1; // points to ']' + 1 (maybe ':' or '/')
                    }
                }
            }

            // Handle IPv4 / hostname (no brackets)
            if (after_host == NULL)
            {
                const char* slash = strchr(h_start, '/');
                const char* colon = strchr(h_start, ':');

                if (slash == NULL)
                {
                    // No path at all -> the whole rest is host (optional :port)
                    slash = url + StrLen((char*)url);
                }

                if (colon != NULL && colon < slash)
                {
                    // host:port
                    UINT hlen = (UINT)(colon - h_start);
                    if (hlen > 0 && hlen < host_sz)
                    {
                        Copy(host, h_start, hlen);
                        host[hlen] = 0;
                        after_host = colon;
                    }
                }
                else
                {
                    // host only
                    UINT hlen = (UINT)(slash - h_start);
                    if (hlen > 0 && hlen < host_sz)
                    {
                        Copy(host, h_start, hlen);
                        host[hlen] = 0;
                        after_host = slash;
                    }
                }
            }

            // Optional explicit port
            if (after_host != NULL && *after_host == ':')
            {
                const char* port_begin = after_host + 1;
                const char* port_end = strchr(port_begin, '/');
                char portbuf[16];
                UINT copylen;

                if (port_end == NULL) port_end = url + StrLen((char*)url);
                copylen = (UINT)(port_end - port_begin);
                if (copylen >= sizeof(portbuf)) copylen = (UINT)sizeof(portbuf) - 1;

                Copy(portbuf, port_begin, copylen);
                portbuf[copylen] = 0;

                {
                    UINT parsed = (UINT)ToInt(portbuf);
                    if (parsed > 0) *port = parsed;
                }

                after_host = port_end;
            }

            // Path (ensure at least "/")
            if (after_host != NULL)
            {
                if (*after_host == '/')
                {
                    if (StrLen((char*)after_host) < path_sz)
                    {
                        StrCpy(path, (UINT)path_sz, (char*)after_host);
                        res = OIDC_OK;
                    }
                }
                else
                {
                    // No slash -> use "/"
                    if (path_sz >= 2)
                    {
                        StrCpy(path, (UINT)path_sz, "/");
                        res = OIDC_OK;
                    }
                }
            }
        }
    }

    return res;
}

OIDC_STATUS OidcHttpsPostForm(const char* host, UINT port, const char* path, const char* form_body, char** out_body, UINT timeout_ms, bool use_tls)
{
    // Always initialize out_body for the caller
    if (out_body != NULL)
    {
        *out_body = NULL;
    }

    OIDC_STATUS res = OIDC_ERR_INTERNAL;

    // Validate inputs (early return allowed by your style)
    if (!IsEmptyStr((char*)host) && !IsEmptyStr((char*)path) && form_body != NULL && out_body != NULL)
    {
        SOCK* socket = NULL;
        HTTP_HEADER* request = NULL;
        HTTP_HEADER* response = NULL;

        InitNetwork();

        do
        {
            char host_buf[256];
            const char* connect_host = host;

            if (StrCmpi((char*)host, "localhost") == 0)
            {
                // Force IPv4 to avoid ::1 when server listens only on 127.0.0.1
                StrCpy(host_buf, sizeof(host_buf), "127.0.0.1");
                connect_host = host_buf;
            }

            // 1) TCP connect
            bool cancel_flag = false;
            UINT nat_t_error_code = 0;
            bool try_start_ssl = false;
            bool no_get_hostname = true;
            UINT ssl_err = 0;
            SSL_VERIFY_OPTION ssl_option;
            Zero(&ssl_option, sizeof(ssl_option));
            IP ret_ip;
            Zero(&ret_ip, sizeof(ret_ip));

            socket = ConnectEx5(
                (char*)connect_host,  // hostname
                port,                 // port
                timeout_ms,           // timeout
                &cancel_flag,         // cancel flag ptr
                NULL,                 // nat_t_svc_name
                &nat_t_error_code,    // nat_t_error_code
                try_start_ssl,        // try_start_ssl
                no_get_hostname,      // no_get_hostname
                &ssl_option,          // ssl_option
                &ssl_err,             // ssl_err
                NULL,                 // hint_str
                &ret_ip               // ret_ip
            );

            if (socket == NULL)
            {
                char ipstr[64]; IPToStr(ipstr, sizeof(ipstr), &ret_ip);
                Debug("ConnectEx5 failed: host=%s port=%u resolved=%s err=%u nat_err=%u\n",
                    connect_host, port, ipstr, ssl_err, nat_t_error_code);
                break;
            }

            if (use_tls)
            {
                // 2) TLS with default CA and hostname verification
                Zero(&ssl_option, sizeof(ssl_option));
                ssl_option.VerifyPeer = true;
                ssl_option.AddDefaultCA = true;
                ssl_option.VerifyHostname = true;

                if (StartSSLEx3(socket, NULL, NULL, NULL, timeout_ms, (char*)host, &ssl_option, &ssl_err) == false)
                {
                    break;
                }
            }

            SetTimeout(socket, timeout_ms);

            // 3) Build Host header (append :port if non-default)
            char host_header[512];
            BuildHostHeader(host, port, use_tls, host_header, sizeof(host_header));

            // 4) Build request headers
            // Build headers
            UINT body_len = (UINT)StrLen((char*)form_body);

            request = NewHttpHeader("POST", (char*)path, "HTTP/1.1");
            AddHttpValue(request, NewHttpValue("Host", host_header));
            AddHttpValue(request, NewHttpValue("User-Agent", "SoftEther-OIDC/1"));
            AddHttpValue(request, NewHttpValue("Accept", "application/json"));
            AddHttpValue(request, NewHttpValue("Accept-Encoding", "identity"));
            AddHttpValue(request, NewHttpValue("Content-Type", "application/x-www-form-urlencoded"));
            {
                char clen[32];
                Format(clen, sizeof(clen), "%u", body_len);
                AddHttpValue(request, NewHttpValue("Content-Length", clen));
            }
            AddHttpValue(request, NewHttpValue("Connection", "close"));

            if (PostHttp(socket, request, (void*)form_body, body_len) == false)
            {
                break;
            }

            FreeHttpHeader(request);
            request = NULL;

            response = RecvHttpHeader(socket);
            if (response == NULL)
            {
                break;
            }

            // Status code (Target holds numeric code as string in Mayaqua)
            if (IsEmptyStr(response->Target) || ToInt(response->Target) / 100 != 2)
            {
                break;
            }

            // Read body (chunked / length / close)
            if (OidcReadHttpBody(socket, response, out_body) == 1)
            {
                res = OIDC_OK;
            }
        } while (0);

        if (response != NULL)
        {
            FreeHttpHeader(response);
            response = NULL;
        }

        if (request != NULL)
        {
            FreeHttpHeader(request);
            request = NULL;
        }

        if (socket != NULL)
        {
            ReleaseSock(socket);
            socket = NULL;
        }

        FreeNetwork();
    }

    return res;
}

OIDC_STATUS OidcHttpsGet(const char* url, char** out_body, UINT timeout_ms)
{
    if (out_body) *out_body = NULL;
    if (IsEmptyStr((char*)url) || out_body == NULL)
        return OIDC_ERR_INTERNAL;

    bool use_tls = false;
    char host[256];
    char path[768];
    UINT port = 0;

    if (OidcHttpParseUrl(url, &use_tls, host, sizeof(host), &port, path, sizeof(path)) != OIDC_OK)
        return OIDC_ERR_INTERNAL;

    OIDC_STATUS res = OIDC_ERR_INTERNAL;
    SOCK* socket = NULL;
    HTTP_HEADER* request = NULL;
    HTTP_HEADER* response = NULL;

    InitNetwork();

    do
    {
        bool cancel_flag = false;
        UINT nat_t_error_code = 0;
        bool try_start_ssl = false;
        bool no_get_hostname = true;
        UINT ssl_err = 0;
        SSL_VERIFY_OPTION ssl_option;
        Zero(&ssl_option, sizeof(ssl_option));
        IP ret_ip;
        Zero(&ret_ip, sizeof(ret_ip));

        socket = ConnectEx5((char*)host, port, timeout_ms, &cancel_flag,
                            NULL, &nat_t_error_code, try_start_ssl, no_get_hostname,
                            &ssl_option, &ssl_err, NULL, &ret_ip);
        if (socket == NULL)
            break;

        if (use_tls)
        {
            Zero(&ssl_option, sizeof(ssl_option));
            ssl_option.VerifyPeer = true;
            ssl_option.AddDefaultCA = true;
            ssl_option.VerifyHostname = true;
            if (StartSSLEx3(socket, NULL, NULL, NULL, timeout_ms, (char*)host, &ssl_option, &ssl_err) == false)
                break;
        }

        SetTimeout(socket, timeout_ms);

        char host_header[512];
        BuildHostHeader(host, port, use_tls, host_header, sizeof(host_header));

        request = NewHttpHeader("GET", (char*)path, "HTTP/1.1");
        AddHttpValue(request, NewHttpValue("Host", host_header));
        AddHttpValue(request, NewHttpValue("User-Agent", "SoftEther-OIDC/1"));
        AddHttpValue(request, NewHttpValue("Accept", "application/json"));
        AddHttpValue(request, NewHttpValue("Accept-Encoding", "identity"));
        AddHttpValue(request, NewHttpValue("Connection", "close"));

        if (SendHttpHeader(socket, request) == false)
            break;

        FreeHttpHeader(request);
        request = NULL;

        response = RecvHttpHeader(socket);
        if (response == NULL)
            break;

       if (IsEmptyStr(response->Target) || ToInt(response->Target) / 100 != 2)
            break;

        if (OidcReadHttpBody(socket, response, out_body) == 1)
            res = OIDC_OK;

    } while (0);

    if (response) FreeHttpHeader(response);
    if (request) FreeHttpHeader(request);
    if (socket) ReleaseSock(socket);

    FreeNetwork();
    return res;
}
