// OidcClientCore.c - Common OIDC helpers: endpoints, authorize URL, code->token

#include "OidcClientCore.h"
#include "OidcHttp.h"          // HTTPS POST helper
#include "Mayaqua/Str.h"
#include "Mayaqua/Memory.h"
#include <string.h>            // strchr

/* Internal helper: pick Keycloak vs generic tail and append to issuer */
static OIDC_STATUS OidcBuildEndpointInternal(const char* issuer, const char* keycloak_tail, const char* generic_tail, char* out, size_t outsz)
{
    OIDC_STATUS res = OIDC_ERR_INTERNAL;

    /* Always sanitize output buffer if available */
    if (out != NULL && outsz > 0)
    {
        out[0] = 0;
    }

    /* Validate inputs (keep single return at end) */
    if (issuer != NULL &&
        !IsEmptyStr((char*)issuer) &&
        keycloak_tail != NULL &&
        generic_tail != NULL &&
        out != NULL &&
        outsz > 0)
    {
        size_t n = StrLen((char*)issuer);

        /* Trim trailing slashes */
        while (n > 0 && issuer[n - 1] == '/')
        {
            n--;
        }

        /* Pick Keycloak tail if issuer contains /realms/, otherwise generic */
        {
            const char* tail = InStr((char*)issuer, "/realms/") ? keycloak_tail : generic_tail;
            size_t tail_len = StrLen((char*)tail);

            /* +1 for NUL terminator */
            if (n + tail_len + 1 <= outsz)
            {
                Copy(out, issuer, (UINT)n);
                out[n] = 0;
                StrCat(out, (UINT)outsz, (char*)tail);
                res = OIDC_OK;
            }
        }
    }

    return res;
}

/* Parse JSON and extract id_token (required), access_token (optional),
   refresh_token (required), refresh_expires_in (expires_in) and expires_in (optional).
   ExpiresAt is stored as absolute Unix epoch ms for the access token. */
static OIDC_STATUS OidcFillTokensFromJson(char* json_resp, OIDC_TOKENS* out_tokens)
{
    OIDC_STATUS res = OIDC_ERR_INTERNAL;

    if (out_tokens != NULL)
    {
        Zero(out_tokens, sizeof(*out_tokens));
    }

    if (IsEmptyStr(json_resp) == false && out_tokens != NULL)
    {
        JSON_VALUE* root = JsonParseString(json_resp);

        if (root != NULL)
        {
            JSON_OBJECT* obj = JsonObject(root);

            if (obj != NULL)
            {
                bool id_token_parsed = false;
                {
                    /* id_token is required for success */
                    char* id_token = JsonGetStr(obj, "id_token");
                    id_token_parsed = true;

                    if (IsEmptyStr(id_token) == false)
                    {
                        UINT need = StrLen(id_token) + 1;
                        out_tokens->IdToken = (char*)ZeroMalloc(need);

                        if (out_tokens->IdToken != NULL)
                        {
                            StrCpy(out_tokens->IdToken, need, id_token);
                        }
                    }
                }

                bool refresh_token_parsed = false;
                {
                    /* refresh_token is required for success */
                    char* refresh_token = JsonGetStr(obj, "refresh_token");
                    if (IsEmptyStr(refresh_token) == false)
                    {
                        UINT rneed = StrLen(refresh_token) + 1;
                        out_tokens->RefreshToken = (char*)ZeroMalloc(rneed);
                        if (out_tokens->RefreshToken != NULL)
                        {
                            StrCpy(out_tokens->RefreshToken, rneed, refresh_token);
                            refresh_token_parsed = true;
                        }
                    }
                }

                bool refresh_exp_present = false;
                {
                    /* Optional: refresh_expires_in (seconds). 0 or missing => unknown (no fixed expiry). */
                    UINT64 refresh_exp_s = JsonGetNumber(obj, "refresh_expires_in"); /* returns 0 on fail */
                    if (refresh_exp_s > 0)
                    {
                        UINT64 now_ms = ((UINT64)time(NULL)) * 1000ULL;
                        UINT64 add_ms = refresh_exp_s * 1000ULL;
                        out_tokens->RefreshTokenExpiresAt = now_ms + add_ms;
                        refresh_exp_present = true;
                    }
                    else
                    {
                        out_tokens->RefreshTokenExpiresAt = 0; /* unknown/unbounded */
                    }
                }

                /* Optional: access_token */
                {
                    char* at = JsonGetStr(obj, "access_token");
                    if (IsEmptyStr(at) == false)
                    {
                        UINT aneed = StrLen(at) + 1;
                        out_tokens->AccessToken = (char*)ZeroMalloc(aneed);
                        if (out_tokens->AccessToken != NULL)
                        {
                            StrCpy(out_tokens->AccessToken, aneed, at);
                        }
                    }
                }

                /* Optional: expires_in (seconds) -> store as absolute epoch ms */
                {
                    UINT64 exp_s = JsonGetNumber(obj, "expires_in"); /* returns 0 on fail */
                    if (exp_s > 0)
                    {
                        UINT64 now_ms = ((UINT64)time(NULL)) * 1000ULL;
                        UINT64 add_ms = exp_s * 1000ULL;
                        out_tokens->AccessTokenExpiresAt = now_ms + add_ms;
                    }
                    else
                    {
                        out_tokens->AccessTokenExpiresAt = 0;
                    }
                }


                res = (id_token_parsed && refresh_token_parsed) ? OIDC_OK : OIDC_ERR_INTERNAL;
            }

            JsonFree(root);
        }
    }

    return res;
}

OIDC_STATUS OidcBuildAuthorizeEndpoint(const char* issuer, char* out, size_t outsz)
{
    return OidcBuildEndpointInternal(issuer,
        "/protocol/openid-connect/auth",   // Keycloak
        "/authorize",                      // Generic
        out, outsz);
}

OIDC_STATUS OidcBuildTokenEndpoint(const char* issuer, char* out, size_t outsz)
{
    return OidcBuildEndpointInternal(issuer,
        "/protocol/openid-connect/token",  // Keycloak
        "/token",                          // Generic
        out, outsz);
}

OIDC_STATUS OidcComposeAuthorizeUrl(const OIDC_CONFIG* cfg, const char* code_challenge, const char* state, const char* nonce, char* out_url, size_t out_url_sz)
{
    OIDC_STATUS res = OIDC_ERR_INTERNAL;

    if (cfg != NULL &&
        !IsEmptyStr((char*)cfg->IssuerUrl) &&
        !IsEmptyStr((char*)cfg->ClientId) &&
        !IsEmptyStr((char*)cfg->RedirectUri) &&
        !IsEmptyStr((char*)code_challenge) &&
        !IsEmptyStr((char*)state) &&
        !IsEmptyStr((char*)nonce) &&
        out_url != NULL &&
        out_url_sz > 0)
    {
        out_url[0] = '\0';

        // Build authorize endpoint from issuer
        {
            char authorize_endpoint[1024];
            if (OidcBuildAuthorizeEndpoint(cfg->IssuerUrl, authorize_endpoint, sizeof(authorize_endpoint)) == OIDC_OK)
            {
                const char* scope_used = (cfg->Scopes[0] != '\0') ? cfg->Scopes : "openid";

                // URL-encode all params
                char enc_client[512];
                char enc_redirect[1024];
                char enc_scope[512];
                char enc_challenge[256];
                char enc_state[128];
                char enc_nonce[128];

                if (OidcUrlEncode(cfg->ClientId, enc_client, sizeof(enc_client)) &&
                    OidcUrlEncode(cfg->RedirectUri, enc_redirect, sizeof(enc_redirect)) &&
                    OidcUrlEncode(scope_used, enc_scope, sizeof(enc_scope)) &&
                    OidcUrlEncode(code_challenge, enc_challenge, sizeof(enc_challenge)) &&
                    OidcUrlEncode(state, enc_state, sizeof(enc_state)) &&
                    OidcUrlEncode(nonce, enc_nonce, sizeof(enc_nonce)))
                {
                    char tmp_url[4096];
                    int n = snprintf(
                        tmp_url, sizeof(tmp_url),
                        "%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s"
                        "&code_challenge_method=S256&code_challenge=%s&state=%s&nonce=%s",
                        authorize_endpoint,
                        enc_client,
                        enc_redirect,
                        enc_scope,
                        enc_challenge,
                        enc_state,
                        enc_nonce
                    );

                    if (n >= 0 && (size_t)n < sizeof(tmp_url))
                    {
                        UINT need = (UINT)n + 1;  // include NUL
                        if (need <= (UINT)out_url_sz)
                        {
                            StrCpy(out_url, (UINT)out_url_sz, tmp_url);
                            res = OIDC_OK;

                        }
                    }
                }
            }
        }
    }

    return res;
}

OIDC_STATUS OidcExchangeAuthCodeForTokens(const OIDC_CONFIG* cfg, const char* code, const char* code_verifier, OIDC_TOKENS* out_tokens, UINT timeout_ms)
{
    OIDC_STATUS res = OIDC_ERR_INTERNAL;

    if (out_tokens != NULL)
    {
        Zero(out_tokens, sizeof(*out_tokens));
    }

    if (cfg != NULL &&
        IsEmptyStr((char*)code) == false &&
        IsEmptyStr((char*)code_verifier) == false &&
        out_tokens != NULL)
    {
        /* Resolve token endpoint from issuer */
        char token_endpoint[1024];
        res = OidcBuildTokenEndpoint(cfg->IssuerUrl, token_endpoint, sizeof(token_endpoint));
        if (res == OIDC_OK)
        {
            /* Pre-encode form values */
            char enc_code[1024];
            char enc_client[512];
            char enc_redirect[1024];
            char enc_verifier[256];

            if (OidcUrlEncode(code, enc_code, sizeof(enc_code)) &&
                OidcUrlEncode(cfg->ClientId, enc_client, sizeof(enc_client)) &&
                OidcUrlEncode(cfg->RedirectUri, enc_redirect, sizeof(enc_redirect)) &&
                OidcUrlEncode(code_verifier, enc_verifier, sizeof(enc_verifier)))
            {
                /* Compose application/x-www-form-urlencoded body (no spaces!) */
                char form[4096];
                int n = snprintf(
                    form,
                    sizeof(form),
                    "grant_type=authorization_code&code=%s&client_id=%s&redirect_uri=%s&code_verifier=%s",
                    enc_code,
                    enc_client,
                    enc_redirect,
                    enc_verifier);

                if (n >= 0 && (size_t)n < sizeof(form))
                {
                    /* Split https://host[:port]/path for the POST */
                    char host[256];
                    char path[768];
                    UINT port = 0;
                    bool use_tls = false;
                    res = OidcHttpParseUrl(token_endpoint, &use_tls, host, sizeof(host), &port, path, sizeof(path));
                    if (res == OIDC_OK)
                    {
                        char* json_resp = NULL;
                        res = OidcHttpsPostForm(host, port, path, form, &json_resp, timeout_ms, use_tls);
                        if (res == OIDC_OK)
                        {
                            if (json_resp != NULL)
                            {
                                res = OidcFillTokensFromJson(json_resp, out_tokens);
                                if (res == OIDC_OK)
                                {
                                    /* success: out_tokens->IdToken is set, refresh_token is set, AccessToken/ExpiresAt may be set */
                                    res = OIDC_OK;
                                }
                            }
                            else
                            {
                                res = OIDC_ERR_PROVIDER;
                            }
                        }

                        if (json_resp != NULL)
                        {
                            SecureZero(json_resp, StrLen(json_resp));
                            Free(json_resp);
                            json_resp = NULL;
                        }
                    }
                }
            }
        }
    }
    return res;
}

OIDC_STATUS OidcExchangeRefreshForTokens(const OIDC_CONFIG* cfg, const char* refresh_token, OIDC_TOKENS* out_tokens, UINT timeout_ms)
{
    OIDC_STATUS res = OIDC_ERR_INTERNAL;

    if (out_tokens != NULL)
    {
        Zero(out_tokens, sizeof(*out_tokens));
    }

    if (cfg != NULL && IsEmptyStr((char*)refresh_token) == false && out_tokens != NULL)
    {
        char token_endpoint[1024];
        if (OidcBuildTokenEndpoint(cfg->IssuerUrl, token_endpoint, sizeof(token_endpoint)) == OIDC_OK)
        {
            char enc_refresh[2048];
            char enc_client[512];

            if (OidcUrlEncode(refresh_token, enc_refresh, sizeof(enc_refresh)) &&
                OidcUrlEncode(cfg->ClientId, enc_client, sizeof(enc_client)))
            {
                char form[4096];
                int n = snprintf(form, sizeof(form),
                    "grant_type=refresh_token&refresh_token=%s&client_id=%s",
                    enc_refresh, enc_client);

                if (n >= 0 && (size_t)n < sizeof(form))
                {
                    bool use_tls = false;
                    char host[256];
                    char path[768];
                    UINT port = 0;
                    char* json = NULL;

                    if (OidcHttpParseUrl(token_endpoint, &use_tls, host, sizeof(host), &port, path, sizeof(path)) == OIDC_OK)
                    {
                        if (OidcHttpsPostForm(host, port, path, form, &json, timeout_ms, use_tls) == OIDC_OK && json != NULL)
                        {
                            if (OidcFillTokensFromJson(json, out_tokens) == OIDC_OK)
                            {
                                res = OIDC_OK;
                            }

                            SecureZero(json, StrLen(json));
                            Free(json);
                            json = NULL;
                        }
                    }
                }
            }
        }
    }

    return res;
}
