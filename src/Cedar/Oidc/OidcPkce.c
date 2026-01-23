// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
//
// OidcPkce.c
// PKCE + base64url using Mayaqua (Rand, Sha2_256, Base64Encode).

#include <string.h>
#include "OidcPkce.h"

#include "Encrypt.h"     // Rand, Sha2_256
#include "Encoding.h"    // Base64Encode

/* Generate cryptographically-random bytes using Mayaqua Rand() */
int OidcRandBytes(unsigned char* dst, size_t len)
{
	if (dst == NULL || len == 0)
	{
		return 0;
	}

	Rand(dst, (UINT)len);

	return 1;
}

/* SHA-256 using Mayaqua Sha2_256(out, src, size) */
int OidcSha256(const void* data, size_t len, unsigned char out32[32])
{
	if (data == NULL || out32 == NULL)
	{
		return 0;
	}

	Sha2_256(out32, (void*)data, (UINT)len);

	return 1;
}

/* Base64url (no padding) using Mayaqua Base64Encode + in-place conversion. */
int OidcEncodeBase64UrlNoPad(const unsigned char* in, size_t inlen, char* out, size_t outsz)
{
	UINT need;
	UINT n;
	size_t k;
	size_t i;

	if (in == NULL || out == NULL || outsz == 0)
	{
		return 0;
	}

	/* standard base64 length upper bound = ((n+2)/3)*4 */
	need = (UINT)(((inlen + 2) / 3) * 4);

	if (outsz < (size_t)need + 1)
	{
		return 0;
	}

	/* Mayaqua Base64Encode does standard base64 with '=' padding */
	n = Base64Encode(out, in, (UINT)inlen);

	/* ensure NUL for our in-place transform */
	out[n] = '\0';

	/* convert to base64url and strip '=' */
	k = 0;
	for (i = 0; i < n; i++)
	{
		char c;

		c = out[i];

		if (c == '=')
		{
			continue;
		}

		if (c == '+')
		{
			c = '-';
		}
		else if (c == '/')
		{
			c = '_';
		}

		out[k] = c;
		k++;
	}

	out[k] = '\0';

	return 1;
}

/* ----- PKCE helpers ----- */

static int Pkce_GenerateVerifier(char* out_verifier, size_t outsz)
{
	unsigned char rnd[32];
	int ok;

	ok = 0;

	if (OidcRandBytes(rnd, sizeof(rnd)))
	{
		if (OidcEncodeBase64UrlNoPad(rnd, sizeof(rnd), out_verifier, outsz))
		{
			ok = 1;
		}
	}

	return ok;
}

static int Pkce_ChallengeFromVerifier(const char* verifier, char* out_challenge, size_t outsz)
{
	unsigned char dig[32];
	size_t vlen;
	int ok;

	ok = 0;

	if (verifier == NULL)
	{
		return 0;
	}

	vlen = strlen(verifier);

	if (OidcSha256(verifier, vlen, dig))
	{
		if (OidcEncodeBase64UrlNoPad(dig, sizeof(dig), out_challenge, outsz))
		{
			ok = 1;
		}
	}

	return ok;
}

/* Generates code_verifier (43..128) and code_challenge=S256(base64url no-pad) */
OIDC_STATUS OidcGeneratePkce(char* out_verifier, size_t verifier_sz, char* out_challenge, size_t challenge_sz)
{
	OIDC_STATUS st;

	st = OIDC_ERR_INTERNAL;

	if (out_verifier == NULL || verifier_sz == 0 || out_challenge == NULL || challenge_sz == 0)
	{
		return st;
	}

	out_verifier[0] = '\0';
	out_challenge[0] = '\0';

	if (Pkce_GenerateVerifier(out_verifier, verifier_sz))
	{
		size_t vlen;

		vlen = strlen(out_verifier);

		if (vlen >= 43 && vlen <= OIDC_PKCE_VERIFIER_MAX)
		{
			if (Pkce_ChallengeFromVerifier(out_verifier, out_challenge, challenge_sz))
			{
				st = OIDC_OK;
			}
		}
	}

	return st;
}
