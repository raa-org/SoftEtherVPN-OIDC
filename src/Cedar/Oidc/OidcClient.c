// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module

// OIDCClient.c
// build /authorize with PKCE, open browser, env override for ID token.
// No internal caching; caller owns buffers and frees via OidcClientFreeTokens().

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"   // Zero
#include "Mayaqua/Str.h"      // StrCmpi, IsEmptyStr
#include "Mayaqua/Kernel.h"   // THREAD, Wait, NewThread, WaitThreadInit, WaitThread
#include "Mayaqua/Object.h"   // EVENT, NewEvent, ReleaseEvent
#include "Mayaqua/Encrypt.h"

#include "Cedar/CedarType.h"
#include "Cedar/Connection.h"

#include "OidcClient.h"
#include "OidcClientCore.h"
#include "OidcPkce.h"              // OidcGeneratePkce, OIDC_PKCE_VERIFIER_MAX, OIDC_PKCE_BUF
#include "OidcUrlEncoding.h"       // OidcUrlEncode
#include "OidcInteractiveUI.h"     // OidcOpenSystemBrowser
#include "OidcLoopback.h"

#include "OidcSecureStore.h"
#include "OidcJwt.h"

#include "OidcLog.h"

#include <string.h>
#include <stdlib.h>

#define OIDC_LOOPBACK_MAX_WAIT_MS   (120u * 1000u)  // 2 minutes
#define OIDC_UI_CLOSE_GRACE_MS      (500u)          // 0.5 second

static OIDC_UI_BRIDGE g_OidcUiBridge;
static bool g_OidcUiBridgeEnabled = false;

/* Small allocator that uses Mayaqua memory helpers */
static char* OidcAllocCopy(const char* s)
{
	char* p;
	UINT n;

	if (IsEmptyStr(s))
	{
		return NULL;
	}

	n = StrLen(s) + 1;

	p = (char*)ZeroMalloc(n);
	if (p != NULL)
	{
		StrCpy(p, n, s);
	}

	return p;
}

// worker context
typedef struct LOOPBACK_WORKER_CONTEXT {
	OIDC_LOOPBACK* loop;
	char* code;     UINT code_sz;
	char* state;    UINT state_sz;
	volatile int result;   // 1=ok, 0=timeout/none, <0=error
	EVENT* done_evt;
} LOOPBACK_WORKER_CONTEXT;

static void LoopbackWaitThread(THREAD* t, void* param)
{
	LOOPBACK_WORKER_CONTEXT* context = (LOOPBACK_WORKER_CONTEXT*)param;

	NoticeThreadInit(t);

	context->result = OidcLoopbackWait(context->loop, context->code, context->code_sz, context->state, context->state_sz);
	if (context->done_evt)
	{
		Set(context->done_evt);
	}
}

bool OidcBuildAccountKey(char* out_key, UINT out_key_size, const char* issuer_url, const char* client_id)
{
	UCHAR hash[SHA256_SIZE];
	BUF* b;

	if (out_key == NULL || out_key_size < OIDC_ACCOUNT_KEY_SHA256_HEX_BUF_SIZE)
		return false;

	if (IsEmptyStr(issuer_url) || IsEmptyStr(client_id))
		return false;

	b = NewBuf();
	WriteBuf(b, issuer_url, StrLen(issuer_url));
	WriteBuf(b, "|", 1);
	WriteBuf(b, client_id, StrLen(client_id));

	Zero(hash, sizeof(hash));
	Sha2_256(hash, b->Buf, b->Size);

	FreeBuf(b);

	Zero(out_key, out_key_size);
	BinToStr(out_key, out_key_size, hash, sizeof(hash));

	return true;
}

// ===== Public API =====

void OidcClientSetUiBridge(const OIDC_UI_BRIDGE* bridge)
{
	if (bridge != NULL && bridge->Open != NULL && bridge->WaitClosed != NULL)
	{
		Copy(&g_OidcUiBridge, bridge, sizeof(OIDC_UI_BRIDGE));
		g_OidcUiBridgeEnabled = true;
	}
	else
	{
		Zero(&g_OidcUiBridge, sizeof(g_OidcUiBridge));
		g_OidcUiBridgeEnabled = false;
	}
}
bool OidcClientIsEmbeddedUiPurgeSupported(void)
{
	return (g_OidcUiBridgeEnabled && g_OidcUiBridge.PurgeAccountData != NULL);
}

OIDC_STATUS OidcClientForgetEmbeddedUiData(const OIDC_CONFIG* oidc_cfg, UINT timeout_ms)
{
	char key[OIDC_ACCOUNT_KEY_SHA256_HEX_BUF_SIZE];

	if (oidc_cfg == NULL || IsEmptyStr(oidc_cfg->IssuerUrl) || IsEmptyStr(oidc_cfg->ClientId))
		return OIDC_ERR_INVALID_PARAM;

	if (timeout_ms == 0)
		timeout_ms = OIDC_UI_PURGE_DEFAULT_TIMEOUT_MS;

	Zero(key, sizeof(key));
	if (!OidcBuildAccountKey(key, sizeof(key), oidc_cfg->IssuerUrl, oidc_cfg->ClientId))
		return OIDC_ERR_INVALID_PARAM;

	if (!g_OidcUiBridgeEnabled || g_OidcUiBridge.PurgeAccountData == NULL)
		return OIDC_ERR_NOT_SUPPORTED;

	if (g_OidcUiBridge.PurgeAccountData(key, timeout_ms, g_OidcUiBridge.UserData))
		return OIDC_OK;

	return OIDC_ERR_INTERNAL;
}

OIDC_STATUS OidcClientForgetEmbeddedUiDataByKey(const char* account_key, UINT timeout_ms)
{
	if (IsEmptyStr(account_key))
		return OIDC_ERR_INVALID_PARAM;

	if (timeout_ms == 0)
		timeout_ms = OIDC_UI_PURGE_DEFAULT_TIMEOUT_MS;

	if (!OidcClientIsEmbeddedUiPurgeSupported())
		return OIDC_ERR_NOT_SUPPORTED;

	return g_OidcUiBridge.PurgeAccountData(account_key, timeout_ms, g_OidcUiBridge.UserData)
		? OIDC_OK
		: OIDC_ERR_INTERNAL;
}

OIDC_STATUS ClientEnsureOidcIdToken(CLIENT_AUTH* auth)
{
	bool have_id_token = false;

	if (auth == NULL || auth->AuthType != CLIENT_AUTHTYPE_OIDC)
	{
		return OIDC_ERR_INVALID_PARAM;
	}

	// 1) Check if we already have a usable IdToken in CLIENT_AUTH
	if (!IsEmptyStr(auth->OidcIdToken))
	{
		have_id_token = true;
	}

	OIDC_TOKENS tokens;
	Zero(&tokens, sizeof(tokens));

	// 2) Try silent refresh using stored refresh_token
	if (!have_id_token)
	{
		if (OidcClientTrySilentRefreshWithStoredToken(auth->Username, auth->OidcConfig, &tokens) == OIDC_OK)
		{
			OidcClientFillAuthFromIdToken(auth, tokens.IdToken);

			if (!IsEmptyStr(auth->OidcIdToken))
			{
				have_id_token = true;
			}
		}
	}

	if (have_id_token)
	{
		// We already have IdToken; nothing else to do.
		return OIDC_OK;
	}

	// 3) Fallback to interactive sign-in if still no IdToken
	const OIDC_CONFIG* cfg = auth->OidcConfig;

	if (cfg == NULL)
	{
		// Misconfigured account: no OIDC config for an OIDC auth type.
		return OIDC_ERR_INVALID_PARAM;
	}

	OIDC_STATUS st = OidcClientInteractiveSignIn(auth, cfg, &tokens);

	// Free dynamically allocated token strings (Id/Access/Refresh etc.)
	OidcClientFreeTokens(&tokens);

	// If OIDC client says OK but we still do not have IdToken, treat as invalid token.
	if (st == OIDC_OK && IsEmptyStr(auth->OidcIdToken))
	{
		return OIDC_ERR_INVALID_TOKEN;
	}

	return st;
}

OIDC_STATUS OidcClientInteractiveSignIn(CLIENT_AUTH* auth, const OIDC_CONFIG* oidc_cfg, OIDC_TOKENS* out_tokens)
{
	if (oidc_cfg == NULL || out_tokens == NULL)
	{
		OIDC_LOG_ERROR("OidcClientInteractiveSignIn: invalid arguments (cfg or out_tokens is NULL)");
		return OIDC_ERR_INTERNAL;
	}

	OIDC_LOG_INFO("OidcClientInteractiveSignIn: start interactive sign-in (issuer='%s', client_id='%s')",
		oidc_cfg->IssuerUrl, oidc_cfg->ClientId);

	OIDC_STATUS    res = OIDC_ERR_INTERNAL;
	OIDC_LOOPBACK* loopback = NULL;

	Zero(out_tokens, sizeof(*out_tokens));

	char code_verifier[OIDC_PKCE_VERIFIER_MAX + 1];
	char state[64];
	char nonce[64];
	char auth_code[1024];
	char returned_state[128];

	do
	{
		/* Generate PKCE */
		char code_challenge[OIDC_PKCE_BUF];
		OIDC_STATUS st_pkce = OidcGeneratePkce(code_verifier, sizeof(code_verifier), code_challenge, sizeof(code_challenge));
		if (st_pkce != OIDC_OK)
		{
			res = st_pkce;
			break;
		}

		/* Generate state and nonce */
		unsigned char rnd16[16];

		state[0] = '\0';
		nonce[0] = '\0';

		if (!OidcRandBytes(rnd16, sizeof(rnd16)))
		{
			res = OIDC_ERR_INTERNAL;
			break;
		}
		OidcEncodeBase64UrlNoPad(rnd16, sizeof(rnd16), state, sizeof(state));

		if (!OidcRandBytes(rnd16, sizeof(rnd16)))
		{
			res = OIDC_ERR_INTERNAL;
			break;
		}
		OidcEncodeBase64UrlNoPad(rnd16, sizeof(rnd16), nonce, sizeof(nonce));

		/* Compose authorize URL */
		char authorize_url[4096];
		size_t url_sz = sizeof(authorize_url);

		OIDC_STATUS st_url = OidcComposeAuthorizeUrl(oidc_cfg, code_challenge, state, nonce, authorize_url, url_sz);
		if (st_url != OIDC_OK)
		{
			res = st_url;
			break;
		}

		/* Start loopback listener before opening the browser */
		if (OidcLoopbackStart(&loopback, oidc_cfg->RedirectUri) == 0)
		{
			break;
		}

		int ui_open_ok = 0;

		if (g_OidcUiBridgeEnabled)
		{
			char account_key[OIDC_ACCOUNT_KEY_SHA256_HEX_BUF_SIZE];
			Zero(account_key, sizeof(account_key));

			if (!OidcBuildAccountKey(account_key, sizeof(account_key), oidc_cfg->IssuerUrl, oidc_cfg->ClientId))
			{
				OIDC_LOG_ERROR("OidcClientInteractiveSignIn: cannot build account_key (issuer/client_id missing)");
				res = OIDC_ERR_INVALID_PARAM;
				break;
			}

			ui_open_ok = g_OidcUiBridge.Open(authorize_url, account_key, g_OidcUiBridge.UserData);
		}
		else
		{
			// No external bridge configured -> this is a logic error in service setup.
			res = OIDC_ERR_INTERNAL;
			break;
		}

		if (ui_open_ok == 0)
		{
			res = OIDC_ERR_INTERNAL;
			break;
		}

		/* Wait for the authorization response */
		auth_code[0] = '\0';
		returned_state[0] = '\0';

		LOOPBACK_WORKER_CONTEXT loopbackWorkerContext;
		Zero(&loopbackWorkerContext, sizeof(loopbackWorkerContext));
		loopbackWorkerContext.loop = loopback;
		loopbackWorkerContext.code = auth_code;
		loopbackWorkerContext.code_sz = sizeof(auth_code);
		loopbackWorkerContext.state = returned_state;
		loopbackWorkerContext.state_sz = sizeof(returned_state);
		loopbackWorkerContext.done_evt = NewEvent();

		THREAD* loopbackWaitThread = NewThread(LoopbackWaitThread, &loopbackWorkerContext);
		WaitThreadInit(loopbackWaitThread);

		bool got_redirect = false;
		UINT waited_ms = 0;
		res = OIDC_ERR_INTERNAL;
		while (!got_redirect)
		{
			if (Wait(loopbackWorkerContext.done_evt, 50))
			{
				got_redirect = true;
				break;
			}
			waited_ms += 50;

			bool closed = 0;
			if (g_OidcUiBridgeEnabled && g_OidcUiBridge.WaitClosed != NULL)
			{
				// 1=closed, 0=not yet
				closed = g_OidcUiBridge.WaitClosed(0, g_OidcUiBridge.UserData);
			}
			else
			{
				// No UI bridge -> this is a setup error.
				if (!Wait(loopbackWorkerContext.done_evt, OIDC_UI_CLOSE_GRACE_MS))
				{
					OidcLoopbackCancel(loopback);
					Wait(loopbackWorkerContext.done_evt, INFINITE);
				}
				res = OIDC_ERR_INTERNAL;
				break;
			}

			if (closed)
			{
				// Window was closed before we got the redirect -> user cancel.
				if (!Wait(loopbackWorkerContext.done_evt, OIDC_UI_CLOSE_GRACE_MS))
				{
					OidcLoopbackCancel(loopback);
					Wait(loopbackWorkerContext.done_evt, INFINITE);
				}
				res = OIDC_ERR_USER_CANCELED;
				break;
			}

			if (waited_ms >= OIDC_LOOPBACK_MAX_WAIT_MS)
			{
				OidcLoopbackCancel(loopback);
				Wait(loopbackWorkerContext.done_evt, INFINITE);
				res = OIDC_ERR_TIMEOUT;
				break;
			}
		}

		WaitThread(loopbackWaitThread, INFINITE);

		ReleaseThread(loopbackWaitThread);
		loopbackWaitThread = NULL;

		ReleaseEvent(loopbackWorkerContext.done_evt);
		loopbackWorkerContext.done_evt = NULL;

		if (g_OidcUiBridgeEnabled && g_OidcUiBridge.Close != NULL)
		{
			g_OidcUiBridge.Close(g_OidcUiBridge.UserData);
		}

		if (got_redirect)
		{
			/* Optional CSRF check: state must match (if provider returns it) */
			if (returned_state[0] != '\0' && StrCmpi(returned_state, state) != 0)
			{
				res = OIDC_ERR_PROVIDER;
				break;
			}

			/* Exchange authorization code for tokens */
			OIDC_TOKENS tokens;
			Zero(&tokens, sizeof(tokens));

			OIDC_STATUS st_token = OidcExchangeAuthCodeForTokens(oidc_cfg, auth_code, code_verifier, &tokens, 15000);
			if (st_token != OIDC_OK)
			{
				OidcClientFreeTokens(&tokens);
				res = st_token;
				break;
			}

			if (!OidcClientFillAuthFromIdToken(auth, tokens.IdToken))
			{
				res = OIDC_ERR_INVALID_TOKEN;
				break;
			}

			/* Move IdToken ownership into out_tokens */
			out_tokens->IdToken = tokens.IdToken;
			tokens.IdToken = NULL;

			/* Persist refresh_token (rotation-safe overwrite) */
			if (tokens.RefreshToken != NULL && IsEmptyStr(tokens.RefreshToken) == false)
			{
				OIDC_STATUS st_save = OidcStoreRefreshSave(oidc_cfg, auth->Username, tokens.RefreshToken, tokens.RefreshTokenExpiresAt);

				if (st_save != OIDC_OK)
				{
					Debug("WARNING: failed to save refresh_token to secure store.\n");
				}
			}

			/* Client does not track expiry or access token at this phase */
			out_tokens->AccessToken = NULL;
			out_tokens->AccessTokenExpiresAt = 0;

			OidcClientFreeTokens(&tokens);

			res = OIDC_OK;
		}
	} while (0);

	if (loopback != NULL)
	{
		OidcLoopbackStop(loopback);
		loopback = NULL;
	}

	/* Also wipe local scratch secrets in this scope */
	SecureZero(auth_code, sizeof(auth_code));
	SecureZero(code_verifier, sizeof(code_verifier));
	SecureZero(state, sizeof(state));
	SecureZero(nonce, sizeof(nonce));
	SecureZero(returned_state, sizeof(returned_state));

	return res;
}

OIDC_STATUS OidcClientTrySilentRefreshWithStoredToken(char* username, const OIDC_CONFIG* oidc_cfg, OIDC_TOKENS* out_tokens)
{
	OIDC_STATUS status = OIDC_ERR_INTERNAL;

	if (oidc_cfg == NULL || out_tokens == NULL)
	{
		return OIDC_ERR_INTERNAL;
	}

	Zero(out_tokens, sizeof(*out_tokens));

	char* refresh = NULL;
	UINT64 refresh_exp = 0;

	status = OidcStoreRefreshLoad(oidc_cfg, username, &refresh, &refresh_exp);
	if (status == OIDC_OK && refresh != NULL)
	{
		bool usable = true;

		if (refresh_exp > 0)
		{
			UINT64 now_ms = ((UINT64)time(NULL)) * 1000ULL;
			usable = (now_ms < refresh_exp);
		}

		if (usable)
		{
			OIDC_TOKENS tmp;
			Zero(&tmp, sizeof(tmp));

			status = OidcExchangeRefreshForTokens(oidc_cfg, refresh, &tmp, 15000 /*ms*/);
			if (status == OIDC_OK && IsEmptyStr(tmp.IdToken) == false)
			{
				/* Move tokens out; caller decides what to use */
				out_tokens->IdToken = tmp.IdToken;
				tmp.IdToken = NULL;

				out_tokens->AccessToken = tmp.AccessToken;
				tmp.AccessToken = NULL;

				out_tokens->AccessTokenExpiresAt = tmp.AccessTokenExpiresAt;

				out_tokens->RefreshToken = tmp.RefreshToken;
				tmp.RefreshToken = NULL;

				out_tokens->RefreshTokenExpiresAt = tmp.RefreshTokenExpiresAt;
			}
			else
			{
				/* If refresh is invalid/expired server-side, purge it */
				if (status == OIDC_ERR_PROVIDER || status == OIDC_ERR_INVALID_TOKEN)
				{
					(void)OidcStoreRefreshClear(oidc_cfg, username);
				}
			}

			OidcClientFreeTokens(&tmp);
		}
		else
		{
			/* Local expiry known and passed: clear stale token */
			(void)OidcStoreRefreshClear(oidc_cfg, username);
			status = OIDC_ERR_INVALID_TOKEN;
		}

		/* Always wipe the loaded refresh string */
		SecureZero(refresh, StrLen(refresh));
		Free(refresh);
		refresh = NULL;
	}

	return status;
}

// Service-side helper: store refresh token for this user/config.
OIDC_STATUS OidcClientStoreRefreshForUser(const char* username, const OIDC_CONFIG* oidc_cfg, const char* refresh_token, UINT64 expires_at_ms)
{
	if (IsEmptyStr(username) || oidc_cfg == NULL || IsEmptyStr(refresh_token))
	{
		return OIDC_ERR_INVALID_PARAM;
	}

	OIDC_STATUS st_save = OidcStoreRefreshSave(oidc_cfg, username, refresh_token, expires_at_ms);

	if (st_save != OIDC_OK)
	{
		Debug("WARNING: failed to save refresh_token to secure store.\n");
	}

	return st_save;
}


OIDC_STATUS OidcClientHasStoredRefreshForUser(char* username, const OIDC_CONFIG* oidc_cfg, bool* out_has)
{
	if (out_has)
	{
		*out_has = false;
	}

	if (oidc_cfg == NULL || out_has == NULL)
	{
		return OIDC_ERR_INTERNAL;
	}

	if (username == NULL || IsEmptyStr(username))
	{
		*out_has = false;
		return OIDC_OK;
	}

	char* refresh = NULL;
	UINT64 refresh_exp = 0;

	OIDC_STATUS status = OidcStoreRefreshLoad(oidc_cfg, username, &refresh, &refresh_exp);
	if (status == OIDC_OK)
	{
		*out_has = true;
		SecureZero(refresh, StrLen(refresh));
		Free(refresh);
	}
	else if (status == OIDC_ERR_STORAGE_NOT_FOUND)
	{
		*out_has = false;
		status = OIDC_OK;
	}

	return status;
}

OIDC_STATUS OidcClientClearRefreshForUser(const char* username, const OIDC_CONFIG* oidc_cfg)
{
	if (username == NULL || oidc_cfg == NULL)
		return OIDC_ERR_INTERNAL;
	return OidcStoreRefreshClear(oidc_cfg, username);
}

bool OidcClientFillAuthFromIdToken(CLIENT_AUTH* auth, const char* id_token)
{
	char username[MAX_USERNAME_LEN + 1];

	if (auth == NULL || IsEmptyStr(id_token))
	{
		return false;
	}

	Zero(username, sizeof(username));

	if (OidcJwtGetUsernameFromIdToken(id_token, username, sizeof(username)) == false)
	{
		return false;
	}

	StrCpy(auth->OidcIdToken, sizeof(auth->OidcIdToken), id_token);
	StrCpy(auth->Username, sizeof(auth->Username), username);

	return true;
}

void OidcSecureFreeToken(char* token)
{
	// Do not compute StrLen on NULL
	if (token != NULL)
	{
		size_t n = StrLen(token);
		if (n > 0)
		{
			SecureZero(token, n);
		}
		Free(token);
	}
}

void OidcClientFreeTokens(OIDC_TOKENS* oidc_tokens)
{
	if (oidc_tokens == NULL)
	{
		return;
	}

	OidcSecureFreeToken(oidc_tokens->AccessToken);
	oidc_tokens->AccessToken = NULL;

	OidcSecureFreeToken(oidc_tokens->IdToken);
	oidc_tokens->IdToken = NULL;

	OidcSecureFreeToken(oidc_tokens->RefreshToken);
	oidc_tokens->RefreshToken = NULL;

	oidc_tokens->AccessTokenExpiresAt = 0;
	oidc_tokens->RefreshTokenExpiresAt = 0;
}

const char* OidcClientErrorToStr(OIDC_STATUS e)
{
	switch (e)
	{
	case OIDC_OK:						return "OK";
	case OIDC_ERR_NOT_SUPPORTED:		return "Not supported on this platform";
	case OIDC_ERR_NOT_IMPLEMENTED:		return "Not implemented on this platform";
	case OIDC_ERR_TIMEOUT:				return "Timeout";
	case OIDC_ERR_NETWORK:				return "Network error";
	case OIDC_ERR_USER_CANCELED:		return "User canceled";
	case OIDC_ERR_INVALID_PARAM:		return "Invalid param";
	case OIDC_ERR_PROVIDER:				return "Provider error";
	case OIDC_ERR_INVALID_TOKEN:		return "Invalid token";
	case OIDC_ERR_STORAGE_NOT_FOUND:	return "Storage not found";
	default:							return "Internal error";
	}
}
