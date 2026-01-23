// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Modul

// OidcJwt.c

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "OidcJwt.h"

#define OIDC_JWT_MAX_PART_LEN   4096
#define OIDC_JWT_MAX_JSON_LEN   8192

// ---- base64url helpers ----

static int OidcJwtB64CharValue(char c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+' || c == '-') return 62;   // '-' in base64url
	if (c == '/' || c == '_') return 63;   // '_' in base64url
	if (c == '=') return 0;
	return -1;
}

static bool OidcJwtBase64UrlDecode(const char* in, char* out, UINT out_size)
{
	if (in == NULL || out == NULL || out_size == 0)
	{
		return false;
	}

	UINT in_len = (UINT)StrLen((char*)in);
	if (in_len == 0)
	{
		return false;
	}

	UINT mod = in_len % 4;
	if (mod == 1)
	{
		// invalid lenght
		return false;
	}
	UINT pad = (mod == 0) ? 0 : (4 - mod);

	UINT total_len = in_len + pad;
	char* b64 = (char*)ZeroMalloc(total_len + 1);
	if (b64 == NULL)
	{
		return false;
	}

	// '-' -> '+', '_' -> '/'
	for (UINT i = 0; i < in_len; ++i)
	{
		char c = in[i];
		if (c == '-') c = '+';
		else if (c == '_') c = '/';
		b64[i] = c;
	}
	for (UINT i = 0; i < pad; ++i)
	{
		b64[in_len + i] = '=';
	}
	b64[total_len] = 0;

	UINT out_pos = 0;

	for (UINT i = 0; i < total_len; i += 4)
	{
		char c0 = b64[i + 0];
		char c1 = b64[i + 1];
		char c2 = b64[i + 2];
		char c3 = b64[i + 3];

		int v0 = OidcJwtB64CharValue(c0);
		int v1 = OidcJwtB64CharValue(c1);
		int v2 = OidcJwtB64CharValue(c2);
		int v3 = OidcJwtB64CharValue(c3);

		if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0)
		{
			Free(b64);
			return false;
		}

		int pad_bytes = 0;
		if (c3 == '=') pad_bytes++;
		if (c2 == '=') pad_bytes++;

		UINT triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;

		// need space for 3 - pad_bytes + '\0' (at the end of whole buffer)
		if (out_pos + 3 - pad_bytes >= out_size)
		{
			Free(b64);
			return false;
		}

		out[out_pos++] = (char)((triple >> 16) & 0xFF);
		if (pad_bytes < 2)
		{
			out[out_pos++] = (char)((triple >> 8) & 0xFF);
		}
		if (pad_bytes < 1)
		{
			out[out_pos++] = (char)(triple & 0xFF);
		}
	}

	if (out_pos >= out_size)
	{
		Free(b64);
		return false;
	}

	out[out_pos] = 0; // zero-termination JSON

	Free(b64);
	return true;
}

// ---- Very simple string-based claim lookup in JSON ----
// We search for `"claim" : "value"` without a full JSON parser.
// For our id_tokens this is usually more than enough.
static bool OidcJwtExtractStringClaim(const char* json,
	const char* claim,
	char* out,
	UINT out_size)
{
	if (json == NULL || claim == NULL || out == NULL || out_size == 0)
	{
		return false;
	}

	char pattern[64];
	Zero(pattern, sizeof(pattern));

	// pattern = "\"email\"" or "\"preferred_username\"" and etc.
	Format(pattern, sizeof(pattern), "\"%s\"", claim);

	char* p = strstr(json, pattern);
	if (p == NULL)
	{
		return false;
	}

	p += StrLen(pattern);

	// spaces
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
	{
		p++;
	}

	if (*p != ':')
	{
		return false;
	}
	p++;

	// spaces after ':'
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
	{
		p++;
	}

	if (*p != '\"')
	{
		// expected a string claim
		return false;
	}
	p++; // right after the opening quote

	UINT rem = out_size;
	char* dst = out;

	if (rem == 0)
	{
		return false;
	}

	while (*p && *p != '\"')
	{
		char c = *p++;

		if (c == '\\')
		{
			// escape handling
			if (*p == 0)
			{
				break;
			}
			c = *p++;
		}

		if (rem <= 1)
		{
			// no space for the character + '\0'
			*dst = 0;
			return false;
		}

		*dst++ = c;
		rem--;
	}

	*dst = 0;
	return true;
}

bool OidcJwtGetUsernameFromIdToken(const char* jwt, char* out_username, UINT out_username_size)
{
	if (jwt == NULL || out_username == NULL || out_username_size == 0)
	{
		return false;
	}

	// JWT = header.payload.signature
	const char* p1 = strchr(jwt, '.');
	if (p1 == NULL)
	{
		return false;
	}

	const char* payload_start = p1 + 1;
	const char* p2 = strchr(payload_start, '.');

	UINT payload_len = 0;
	if (p2 != NULL)
	{
		payload_len = (UINT)(p2 - payload_start);
	}
	else
	{
		payload_len = (UINT)StrLen((char*)payload_start);
	}

	if (payload_len == 0 || payload_len >= OIDC_JWT_MAX_PART_LEN)
	{
		return false;
	}

	char payload_b64url[OIDC_JWT_MAX_PART_LEN];
	Zero(payload_b64url, sizeof(payload_b64url));
	Copy(payload_b64url, payload_start, payload_len);
	payload_b64url[payload_len] = 0;

	char json[OIDC_JWT_MAX_JSON_LEN];
	Zero(json, sizeof(json));

	if (!OidcJwtBase64UrlDecode(payload_b64url, json, sizeof(json)))
	{
		return false;
	}

	// 1) email
	if (OidcJwtExtractStringClaim(json, "email", out_username, out_username_size))
	{
		return true;
	}

	// 2) preferred_username
	if (OidcJwtExtractStringClaim(json, "preferred_username", out_username, out_username_size))
	{
		return true;
	}

	// 3) sub
	if (OidcJwtExtractStringClaim(json, "sub", out_username, out_username_size))
	{
		return true;
	}

	return false;
}
