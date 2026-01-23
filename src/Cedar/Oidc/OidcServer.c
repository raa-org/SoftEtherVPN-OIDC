// ======================================================================
// OidcServer.c - SoftEtherVPN (Cedar) - OIDC / JWT validation
// ======================================================================

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"   // Zero
#include "Mayaqua/Str.h"      // StrCmpi, IsEmptyStr
#include "Cedar/Cedar.h"
#include "OidcHttp.h"

#include <jwt.h>   // libjwt (https://github.com/benmcollins/libjwt)
#include <stdarg.h>
#include <stdio.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "OidcServer.h"

// Environment variables:
// - SE_OIDC_PUBKEY_PEM: static public key (PEM) used to verify tokens
// - SE_OIDC_JWKS_URI:   JWKS endpoint to fetch signing keys when PEM is not set

static void oidc_set_err(char *err, UINT err_size, const char *fmt, ...);
static char *oidc_extract_pubkey_from_cert_pem(const char *cert_pem);

static bool oidc_base64url_to_bin(const char* in, unsigned char** out, size_t* out_len)
{
	if (out) *out = NULL;
	if (out_len) *out_len = 0;
	if (IsEmptyStr(in) || out == NULL || out_len == NULL) return false;

	size_t n = StrLen((char*)in);
	size_t pad = (4 - (n % 4)) % 4;
	size_t b64_len = n + pad;

	char* b64 = (char*)ZeroMalloc((UINT)b64_len + 1);
	if (b64 == NULL) return false;

	for (size_t i = 0; i < n; i++)
	{
		char c = in[i];
		if (c == '-') c = '+';
		else if (c == '_') c = '/';
		b64[i] = c;
	}
	for (size_t i = 0; i < pad; i++) b64[n + i] = '=';
	b64[b64_len] = 0;

	// EVP_DecodeBlock output is <= input length
	unsigned char* buf = (unsigned char*)ZeroMalloc((UINT)b64_len + 1);
	if (buf == NULL) { Free(b64); return false; }

	int dec = EVP_DecodeBlock(buf, (unsigned char*)b64, (int)b64_len);
	Free(b64);
	if (dec <= 0) { Free(buf); return false; }

	// EVP_DecodeBlock includes decoded bytes for '=' padding; adjust
	while (dec > 0 && buf[dec - 1] == 0x00 && pad > 0)
	{
		// best-effort trim; JWKS fields are DER integers and trailing zeros are unlikely,
		// but EVP may output padding artifacts. We'll use a safer approach:
		break;
	}

	*out = buf;
	*out_len = (size_t)dec;
	return true;
}

static bool oidc_jwt_get_header_kid(const char* jwt, char* out_kid, UINT out_kid_sz)
{
	if (out_kid && out_kid_sz) out_kid[0] = 0;
	if (IsEmptyStr(jwt) || out_kid == NULL || out_kid_sz == 0) return false;

	const char* dot = strchr(jwt, '.');
	if (dot == NULL) return false;

	UINT hlen = (UINT)(dot - jwt);
	if (hlen == 0) return false;

	char* header_b64u = (char*)ZeroMalloc(hlen + 1);
	if (header_b64u == NULL) return false;
	Copy(header_b64u, jwt, hlen);
	header_b64u[hlen] = 0;

	unsigned char* bin = NULL;
	size_t bin_len = 0;
	if (!oidc_base64url_to_bin(header_b64u, &bin, &bin_len))
	{
		Free(header_b64u);
		return false;
	}
	Free(header_b64u);

	// Ensure NUL termination
	char* json_txt = (char*)ZeroMalloc((UINT)bin_len + 1);
	if (json_txt == NULL) { Free(bin); return false; }
	Copy(json_txt, bin, (UINT)bin_len);
	json_txt[bin_len] = 0;
	Free(bin);

	JSON_VALUE* root = JsonParseString(json_txt);
	Free(json_txt);
	if (root == NULL) return false;

	JSON_OBJECT* obj = JsonObject(root);
	if (obj == NULL)
	{
		JsonFree(root);
		return false;
	}

	// JsonGetStr returns a pointer owned by the JSON tree (do not free)
	char* ks = JsonGetStr(obj, "kid");
	if (!IsEmptyStr(ks))
	{
		StrCpy(out_kid, out_kid_sz, ks);
		JsonFree(root);
		return true;
	}

	JsonFree(root);
	return false;
}

static char* oidc_pubkey_pem_from_jwks_rsa(JSON_OBJECT* jwk)
{
	if (jwk == NULL) return NULL;

	char* ns = JsonGetStr(jwk, "n");
	char* es = JsonGetStr(jwk, "e");
	if (IsEmptyStr(ns) || IsEmptyStr(es)) return NULL;

	unsigned char* nbin = NULL; size_t nlen = 0;
	unsigned char* ebin = NULL; size_t elen = 0;
	if (!oidc_base64url_to_bin(ns, &nbin, &nlen)) return NULL;
	if (!oidc_base64url_to_bin(es, &ebin, &elen)) { Free(nbin); return NULL; }

	BIGNUM* bn_n = BN_bin2bn(nbin, (int)nlen, NULL);
	BIGNUM* bn_e = BN_bin2bn(ebin, (int)elen, NULL);
	Free(nbin); Free(ebin);
	if (!bn_n || !bn_e) { if (bn_n) BN_free(bn_n); if (bn_e) BN_free(bn_e); return NULL; }

	RSA* rsa = RSA_new();
	if (!rsa) { BN_free(bn_n); BN_free(bn_e); return NULL; }

	if (RSA_set0_key(rsa, bn_n, bn_e, NULL) != 1)
	{
		RSA_free(rsa); // frees bn_n/bn_e only if set; here not reliably
		BN_free(bn_n); BN_free(bn_e);
		return NULL;
	}

	EVP_PKEY* pkey = EVP_PKEY_new();
	if (!pkey) { RSA_free(rsa); return NULL; }
	if (EVP_PKEY_assign_RSA(pkey, rsa) != 1)
	{
		EVP_PKEY_free(pkey);
		RSA_free(rsa);
		return NULL;
	}

	BIO* out = BIO_new(BIO_s_mem());
	if (!out) { EVP_PKEY_free(pkey); return NULL; }
	if (PEM_write_bio_PUBKEY(out, pkey) != 1)
	{
		BIO_free(out);
		EVP_PKEY_free(pkey);
		return NULL;
	}
	EVP_PKEY_free(pkey);

	char* data = NULL;
	long len = BIO_get_mem_data(out, &data);
	if (len <= 0 || !data) { BIO_free(out); return NULL; }

	char* ret = (char*)ZeroMalloc((UINT)len + 1);
	if (ret) { Copy(ret, data, (UINT)len); ret[len] = 0; }
	BIO_free(out);
	return ret;
}

static bool oidc_fetch_pubkey_pem_from_jwks(const char* jwks_uri, const char* kid, char* out_pem, UINT out_pem_sz, char* err, UINT err_sz)
{
	if (out_pem && out_pem_sz) out_pem[0] = 0;
	if (IsEmptyStr((char*)jwks_uri) || out_pem == NULL || out_pem_sz == 0) return false;

	char* body = NULL;
	if (OidcHttpsGet(jwks_uri, &body, 15000) != OIDC_OK || body == NULL)
	{
		oidc_set_err(err, err_sz, "failed to GET JWKS");
		if (body) Free(body);
		return false;
	}

	JSON_VALUE* root = JsonParseString(body);
	SecureZero(body, StrLen(body));
	Free(body);
	if (!root)
	{
		oidc_set_err(err, err_sz, "invalid JWKS JSON");
		return false;
	}

	JSON_OBJECT* robj = JsonObject(root);
	JSON_ARRAY* keys = (robj != NULL) ? JsonGetArray(robj, "keys") : NULL;
	if (keys == NULL)
	{
		JsonFree(root);
		oidc_set_err(err, err_sz, "JWKS missing keys[]");
		return false;
	}

	JSON_OBJECT* chosen = NULL;
	UINT cnt = JsonArrayGetCount(keys);
	for (UINT i = 0; i < cnt; i++)
	{
		JSON_OBJECT* item = JsonArrayGetObj(keys, i);
		if (item == NULL) continue;

		// Optional "use": if present, must be "sig"
		char* us = JsonGetStr(item, "use");
		if (!IsEmptyStr(us))
		{
			if (StrCmpi(us, "sig") != 0)
				continue;
		}

		if (!IsEmptyStr((char*)kid))
		{
			char* ks = JsonGetStr(item, "kid");
			if (!IsEmptyStr(ks) && StrCmpi(ks, (char*)kid) == 0)
			{
				chosen = item;
				break;
			}
		}
		if (chosen == NULL) chosen = item; // fallback: first usable key
	}

	if (!chosen)
	{
		JsonFree(root);
		oidc_set_err(err, err_sz, "no usable JWKS key");
		return false;
	}

	// Prefer x5c[0] if present
	JSON_ARRAY* x5c = JsonGetArray(chosen, "x5c");
	if (x5c && JsonArrayGetCount(x5c) > 0)
	{
		char* cert_b64 = JsonArrayGetStr(x5c, 0);
		if (!IsEmptyStr(cert_b64))
		{
			// Build CERT PEM then reuse extractor
			char cert_pem[8192];
			Format(cert_pem, sizeof(cert_pem),
			       "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
			       cert_b64);
			char* pub = oidc_extract_pubkey_from_cert_pem(cert_pem);
			if (pub)
			{
				StrCpy(out_pem, out_pem_sz, pub);
				Free(pub);
				JsonFree(root);
				return true;
			}
		}
	}

	// Fallback: RSA n/e
	char* pub2 = oidc_pubkey_pem_from_jwks_rsa(chosen);
	if (pub2)
	{
		StrCpy(out_pem, out_pem_sz, pub2);
		Free(pub2);
		JsonFree(root);
		return true;
	}

	JsonFree(root);
	oidc_set_err(err, err_sz, "unable to build public key from JWKS");
	return false;
}

// ---- Internal helpers -------------------------------------------------

static void oidc_set_err(char *err, UINT err_size, const char *fmt, ...)
{
	if (err == NULL || err_size == 0) return;
	va_list args;
	va_start(args, fmt);
	vsnprintf(err, err_size, fmt, args);
	va_end(args);
}

static void oidc_zero_result(OIDC_VALIDATION_RESULT *r)
{
	if (r) Zero(r, sizeof(*r));
}

// Some environments inject weird newline encodings when copy/pasting PEM into YAML/JSON:
// This sanitizer:
//   - converts `n  -> '\n'
//   - converts \\n -> '\n'
//   - drops any other stray backticks
//   - normalizes CRLF/CR to LF
static char *oidc_sanitize_pem(const char *in)
{
	if (IsEmptyStr(in)) return NULL;

	UINT in_len = StrLen(in);
	// Worst case: output is <= input, allocate input size + 1
	char *out = (char *)ZeroMalloc(in_len + 1);
	if (out == NULL) return NULL;

	UINT j = 0;
	for (UINT i = 0; i < in_len && j < in_len; i++)
	{
		char c = in[i];

		// Normalize CRLF / CR -> LF (skip CR, keep LF)
		if (c == '\r')
		{
			continue;
		}

		// Convert literal `n (backtick + n) into newline
		if (c == '`')
		{
		char next = (i + 1 < in_len) ? in[i + 1] : 0;
			if (next == 'n')
			{
				out[j++] = '\n';
				i++; // consume 'n'
				continue;
			}

			// Otherwise: drop stray backticks
			continue;
		}

		// Convert escaped \n into newline
		if (c == '\\')
		{
			char next = (i + 1 < in_len) ? in[i + 1] : 0;
			if (next == 'n')
			{
				out[j++] = '\n';
				i++; // consume 'n'
				continue;
			}
		}

		out[j++] = c;
	}
	out[j] = 0;
	return out;
}

// If caller provided an X.509 certificate PEM, extract the public key PEM.
static char *oidc_extract_pubkey_from_cert_pem(const char *cert_pem)
{
	if (IsEmptyStr(cert_pem)) return NULL;

	BIO *bio = BIO_new_mem_buf((void *)cert_pem, -1);
	if (bio == NULL) return NULL;

	X509 *x = PEM_read_bio_X509(bio, NULL, 0, NULL);
	BIO_free(bio);
	if (x == NULL) return NULL;

	EVP_PKEY *pkey = X509_get_pubkey(x);
	X509_free(x);
	if (pkey == NULL) return NULL;

	BIO *out = BIO_new(BIO_s_mem());
	if (out == NULL)
	{
		EVP_PKEY_free(pkey);
		return NULL;
	}

	if (PEM_write_bio_PUBKEY(out, pkey) != 1)
	{
		BIO_free(out);
		EVP_PKEY_free(pkey);
		return NULL;
	}

	EVP_PKEY_free(pkey);

	char *data = NULL;
	long len = BIO_get_mem_data(out, &data);
	if (len <= 0 || data == NULL)
	{
		BIO_free(out);
		return NULL;
	}

	char *ret = (char *)ZeroMalloc((UINT)len + 1);
	if (ret != NULL)
	{
		Copy(ret, data, (UINT)len);
		ret[len] = 0;
	}
	BIO_free(out);
	return ret;
}

bool OidcIsProbablyJwt(const char *s)
{
	if (IsEmptyStr(s)) return false;

	// Simple check: exactly two '.' separators and each part non-empty
	UINT dot = 0;
	const char *p = s;
	const char *last = s;
	while (*p)
	{
		if (*p == '.')
		{
			if (p == last) return false; // empty part
			dot++;
			last = p + 1;
		}
		p++;
	}
	if (p == last) return false; // empty tail part
	return (dot == 2);
}

// ---- Claim checks -----------------------------------------------------

static bool oidc_check_time_window(UINT64 now, UINT64 claim, UINT skew, bool is_nbf)
{
	// If claim missing (0)
	if (claim == 0) return true;

	if (is_nbf)
	{
		// Not before: nbf <= now + skew
		return (claim <= (now + (UINT64)skew));
	}
	else
	{
		// Expiry: now <= exp + skew
		return (now <= (claim + (UINT64)skew));
	}
}

// ---- Core validator ---------------------------------------------------

bool OidcValidateIdToken(const char *id_token,
                         const OIDC_SERVER_CONFIG *cfg,
                         OIDC_VALIDATION_RESULT *out,
                         char *err,
                         UINT err_size)
{
	oidc_set_err(err, err_size, "");
	oidc_zero_result(out);

	// Sanity: input
	if (IsEmptyStr(id_token))
	{
		oidc_set_err(err, err_size, "empty id_token");
		return false;
	}
	if (cfg == NULL)
	{
		oidc_set_err(err, err_size, "no config");
		return false;
	}

	// --- Test mode shortcuts --------------------------------
	if (cfg->EnableTestMode)
	{
		if (cfg->AllowAnyStringForTest)
		{
			if (out) { out->SignatureOk = true; out->ExpOk = out->NbfOk = out->IssOk = out->AudOk = true; StrCpy(out->Sub, sizeof(out->Sub), "test-mode"); }
			if (out)
			{
				StrCpy(out->Username, sizeof(out->Username), "test-mode");
			}
			return true;
		}
		if (OidcIsProbablyJwt(id_token))
		{
			// Accept anything that *looks like* a JWT in test mode.
			if (out) { out->SignatureOk = true; out->ExpOk = out->NbfOk = out->IssOk = out->AudOk = true; StrCpy(out->Sub, sizeof(out->Sub), "test-mode"); }
			if (out)
			{
				StrCpy(out->Username, sizeof(out->Username), "test-mode");
			}
			return true;
		}
		oidc_set_err(err, err_size, "test-mode enabled but token is not JWT-like");
		return false;
	}

	// From this point on, we require cryptographic verification via libjwt

	int rc = 0;
	jwt_t *jwt = NULL;

	// Resolve verification key:
	// 1) cfg->StaticPublicKeyPem
	// 2) env SE_OIDC_PUBKEY_PEM
	// 3) env SE_OIDC_JWKS_URI (match by kid)
	// 4) issuer-derived JWKS (Keycloak-style) if cfg->ExpectedIssuer is set
	const char* pem = cfg->StaticPublicKeyPem;
	char pem_dyn[OIDC_MAX_PUBKEY_PEM_LEN + 1];
	Zero(pem_dyn, sizeof(pem_dyn));

	if (IsEmptyStr((char*)pem))
	{
		const char* env_pem = getenv("SE_OIDC_PUBKEY_PEM");
		if (!IsEmptyStr((char*)env_pem))
		{
			StrCpy(pem_dyn, sizeof(pem_dyn), (char*)env_pem);
			pem = pem_dyn;
		}
	}

	char kid_hdr[OIDC_MAX_KID_LEN + 1];
	Zero(kid_hdr, sizeof(kid_hdr));
	(void)oidc_jwt_get_header_kid(id_token, kid_hdr, sizeof(kid_hdr));

	if (IsEmptyStr((char*)pem))
	{
		char jwks_pem[OIDC_MAX_PUBKEY_PEM_LEN + 1];
		Zero(jwks_pem, sizeof(jwks_pem));
		char jwks_err[256];
		Zero(jwks_err, sizeof(jwks_err));

		const char* jwks_uri = getenv("SE_OIDC_JWKS_URI");
		char jwks_uri_buf[1024];
		Zero(jwks_uri_buf, sizeof(jwks_uri_buf));

		if (IsEmptyStr((char*)jwks_uri))
		{
			// Try issuer-derived Keycloak certs endpoint
			if (!IsEmptyStr(cfg->ExpectedIssuer) && InStr(cfg->ExpectedIssuer, "/realms/") != NULL)
			{
				StrCpy(jwks_uri_buf, sizeof(jwks_uri_buf), cfg->ExpectedIssuer);
				// trim trailing slash
				while (StrLen(jwks_uri_buf) > 0 && jwks_uri_buf[StrLen(jwks_uri_buf) - 1] == '/') jwks_uri_buf[StrLen(jwks_uri_buf) - 1] = 0;
				StrCat(jwks_uri_buf, sizeof(jwks_uri_buf), "/protocol/openid-connect/certs");
				jwks_uri = jwks_uri_buf;
			}
		}

		if (!IsEmptyStr((char*)jwks_uri))
		{
			if (oidc_fetch_pubkey_pem_from_jwks(jwks_uri, kid_hdr, jwks_pem, sizeof(jwks_pem), jwks_err, sizeof(jwks_err)))
			{
				StrCpy(pem_dyn, sizeof(pem_dyn), jwks_pem);
				pem = pem_dyn;
			}
			else
			{
				oidc_set_err(err, err_size, "%s", jwks_err);
				return false;
			}
		}
	}

	if (IsEmptyStr((char*)pem))
	{
		oidc_set_err(err, err_size, "no verification key configured (set SE_OIDC_PUBKEY_PEM or SE_OIDC_JWKS_URI)");
		return false;
	}

	// Be robust to escaped or copy/pasted PEM.
	char *pem_sanitized = oidc_sanitize_pem(pem);
	const char *pem_use = (pem_sanitized != NULL) ? pem_sanitized : pem;

	// First attempt: use whatever was provided (public key PEM or sometimes cert PEM).
	rc = jwt_decode(&jwt, id_token, (const unsigned char *)pem_use, StrLen(pem_use));

	// If that failed and it looks like an X.509 certificate PEM, extract the public key and retry.
	if ((rc != 0 || jwt == NULL) && InStr((char *)pem_use, "BEGIN CERTIFICATE") != NULL)
	{
		char *pubkey_pem = oidc_extract_pubkey_from_cert_pem(pem_use);
		if (pubkey_pem != NULL)
		{
			if (jwt) { jwt_free(jwt); jwt = NULL; }
			rc = jwt_decode(&jwt, id_token, (const unsigned char *)pubkey_pem, StrLen(pubkey_pem));
			Free(pubkey_pem);
		}
	}
	if (rc != 0 || jwt == NULL)
	{
		oidc_set_err(err, err_size, "jwt_decode failed (%d)", rc);
		if (jwt) jwt_free(jwt);
		if (pem_sanitized) Free(pem_sanitized);
		return false;
	}
	if (pem_sanitized) Free(pem_sanitized);

	// Header: kid (optional)
	const char *kid = jwt_get_header(jwt, "kid");
	if (out && kid) StrCpy(out->Kid, sizeof(out->Kid), kid);
	if (!IsEmptyStr(cfg->ExpectedKid) && (kid == NULL || StrCmp(cfg->ExpectedKid, kid) != 0))
	{
		oidc_set_err(err, err_size, "kid mismatch");
		jwt_free(jwt);
		return false;
	}

	// Algorithm (for logging)
	if (out) out->Alg = (UINT)jwt_get_alg(jwt);

	// Required: signature verification is implied by successful jwt_decode with key
	if (out) out->SignatureOk = true;

	// Standard time claims
	UINT64 now = (UINT64)(SystemTime64() / 1000ULL);

	UINT64 exp = (UINT64)jwt_get_grant_int(jwt, "exp");
	UINT64 nbf = (UINT64)jwt_get_grant_int(jwt, "nbf");
	UINT64 iat = (UINT64)jwt_get_grant_int(jwt, "iat");

	UINT skew = (cfg->ClockSkewSec == 0 ? 60 : cfg->ClockSkewSec);

	bool exp_ok = oidc_check_time_window(now, exp, skew, false);
	bool nbf_ok = oidc_check_time_window(now, nbf, skew, true);

	if (out)
	{
		out->Exp = exp;
		out->Nbf = nbf;
		out->Iat = iat;
		out->ExpOk = exp_ok;
		out->NbfOk = nbf_ok;
	}
	if (!exp_ok)
	{
		oidc_set_err(err, err_size, "token expired");
		jwt_free(jwt);
		return false;
	}
	if (!nbf_ok)
	{
		oidc_set_err(err, err_size, "token not yet valid");
		jwt_free(jwt);
		return false;
	}

	// iss / aud checks
	const char *iss = jwt_get_grant(jwt, "iss");
	const char *aud = jwt_get_grant(jwt, "aud"); // libjwt returns string (JSON string or first item)

	if (out)
	{
		if (iss) StrCpy(out->Iss, sizeof(out->Iss), iss);
		if (aud) StrCpy(out->Aud, sizeof(out->Aud), aud);
	}

	if (!IsEmptyStr(cfg->ExpectedIssuer))
	{
		bool ok = (iss != NULL && StrCmp(iss, cfg->ExpectedIssuer) == 0);
		if (out) out->IssOk = ok;
		if (!ok)
		{
			oidc_set_err(err, err_size, "issuer mismatch");
			jwt_free(jwt);
			return false;
		}
	}
	else if (out) out->IssOk = true;

	if (!IsEmptyStr(cfg->ExpectedAudience))
	{
		bool ok = (aud != NULL && StrCmp(aud, cfg->ExpectedAudience) == 0);
		if (out) out->AudOk = ok;
		if (!ok)
		{
			oidc_set_err(err, err_size, "audience mismatch");
			jwt_free(jwt);
			return false;
		}
	}
	else if (out) out->AudOk = true;

	// Some useful claims for logging
	const char *sub = jwt_get_grant(jwt, "sub");
	const char *preferred_username = jwt_get_grant(jwt, "preferred_username");
	const char *mapped_username = NULL;

	// Map username from configurable claim; fall back sensibly.
	if (!IsEmptyStr(cfg->UsernameClaim))
	{
		mapped_username = jwt_get_grant(jwt, cfg->UsernameClaim);
	}
	if (IsEmptyStr(mapped_username))
	{
		mapped_username = preferred_username;
	}
	if (IsEmptyStr(mapped_username))
	{
		mapped_username = sub;
	}

	if (out)
	{
		if (sub) StrCpy(out->Sub, sizeof(out->Sub), sub);
		if (preferred_username) StrCpy(out->PreferredUsername, sizeof(out->PreferredUsername), preferred_username);
		if (!IsEmptyStr(mapped_username))
		{
			StrCpy(out->Username, sizeof(out->Username), mapped_username);
		}
	}

	jwt_free(jwt);
	return true;
}
