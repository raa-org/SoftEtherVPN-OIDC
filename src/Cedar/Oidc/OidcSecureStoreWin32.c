// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
//
// OidcSecureStoreWin32.c
// Win32: Secure per-user refresh-token storage (Windows DPAPI + %LOCALAPPDATA%).
// No internal caching; caller owns buffers and frees via OidcClientFreeTokens().

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Encrypt.h"   // Sha2_256
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Crypto/Key.h"

#include "OidcSecureStore.h"

#include <windows.h>
#include <ShlObj.h>        // SHGetKnownFolderPath
#include <KnownFolders.h>  // FOLDERID_LocalAppData
#include <wincrypt.h>      // CryptProtectData / CryptUnprotectData

#ifndef _countof
#define _countof(a) (sizeof(a) / sizeof((a)[0]))
#endif

static const char OIDC_STORE_SUBDIR[] = "\\SoftEtherVPN\\storage\\";
static const char OIDC_ENTROPY_STR[] = "SoftEtherVPN OIDC Refresh v1";
static const char OIDC_LABEL_STR[] = "OIDC info";

// --- Known folder helpers (Windows) ---

// Returns PWSTR allocated by the shell; caller must free with CoTaskMemFree.
static bool GetLocalAppDataKnownFolderW(PWSTR* out_path)
{
	bool res = false;

	if (out_path != NULL)
	{
		*out_path = NULL;

		HRESULT hr = SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, out_path);
		res = SUCCEEDED(hr) && *out_path != NULL;
	}

	return res;
}

// Copies %LOCALAPPDATA% into caller-provided wide buffer.
static bool GetLocalAppDataIntoBufW(wchar_t* out_path, size_t out_capacity_in_characters)
{
	bool res = false;

	if (out_path != NULL && out_capacity_in_characters > 0)
	{
		out_path[0] = L'\0';

		PWSTR p = NULL;
		if (GetLocalAppDataKnownFolderW(&p))
		{
			wcsncpy_s(out_path, out_capacity_in_characters, p, _TRUNCATE);
			CoTaskMemFree(p);
			res = (out_path[0] != L'\0');
		}
	}

	return res;
}

static bool OidcGetStoreDirWin(char* out_dir, UINT out_dir_sz)
{
	bool res = false;

	if (out_dir != NULL && out_dir_sz > 0)
	{
		out_dir[0] = 0;

		wchar_t baseW[MAX_PATH];
		if (GetLocalAppDataIntoBufW(baseW, _countof(baseW)))
		{
			// Convert to UTF-8
			int need = WideCharToMultiByte(CP_UTF8, 0, baseW, -1, NULL, 0, NULL, NULL);
			if (need > 0 && (UINT)need <= out_dir_sz)
			{
				int wrote = WideCharToMultiByte(CP_UTF8, 0, baseW, -1, out_dir, (int)out_dir_sz, NULL, NULL);
				if (wrote > 0)
				{
					StrCat(out_dir, out_dir_sz, (char *)OIDC_STORE_SUBDIR);
					MakeDirEx(out_dir);  // ensure directory exists (recursive)
					res = true;
				}
			}
		}
	}

	return res;
}

// KeyId = hex( SHA256(issuer | client_id | optional subject) )
static bool OidcBuildKeyId(const OIDC_CONFIG* cfg, const char* subject, char* out_key_id, UINT out_key_id_sz)
{
	bool res = false;

	if (out_key_id != NULL && out_key_id_sz > 0 && cfg != NULL &&
		IsEmptyStr((char*)cfg->IssuerUrl) == false &&
		IsEmptyStr((char*)cfg->ClientId) == false)
	{
		out_key_id[0] = 0;

		do
		{
			char cat[1024];

			if (IsEmptyStr((char*)subject))
			{
				Format(cat, sizeof(cat), "%s|%s", cfg->IssuerUrl, cfg->ClientId);
			}
			else
			{
				Format(cat, sizeof(cat), "%s|%s|%s", cfg->IssuerUrl, cfg->ClientId, subject);
			}

			UCHAR h[32];
			Sha2_256(h, cat, (UINT)StrLen(cat));

			// Hex encode into out
			// BinToStrEx produces contiguous hex without separators.
			BinToStrEx(out_key_id, out_key_id_sz, h, (UINT)sizeof(h));
			res = (IsEmptyStr(out_key_id) == false);
		} while (0);
	}

	return res;
}

// DPAPI protect entire plaintext buffer; returns heap BUF with ciphertext.
static bool OidcDpapiProtect(const void* in_plain_text, UINT in_plain_text_len, BUF** out_pblob)
{
	bool res = false;

	if (out_pblob != NULL)
	{
		*out_pblob = NULL;

		if (in_plain_text != NULL && in_plain_text_len > 0)
		{
			DATA_BLOB in_blob = { 0 };
			DATA_BLOB out_blob = { 0 };
			DATA_BLOB entropy = { 0 };

			in_blob.cbData = in_plain_text_len;
			in_blob.pbData = (BYTE*)in_plain_text;

			entropy.cbData = (DWORD)sizeof(OIDC_ENTROPY_STR) - 1;
			entropy.pbData = (BYTE*)OIDC_ENTROPY_STR;

			if (CryptProtectData(&in_blob, OIDC_LABEL_STR, &entropy, NULL, NULL, 0, &out_blob))
			{
				BUF* buf = NewBuf();
				if (buf != NULL)
				{
					WriteBuf(buf, out_blob.pbData, out_blob.cbData);
					*out_pblob = buf;
					res = true;
				}
				LocalFree(out_blob.pbData);
			}
		}
	}

	return res;
}

// DPAPI unprotect ciphertext; returns heap BUF with plaintext.
static bool OidcDpapiUnprotect(const void* in_cipher_text, UINT in_cipher_text_len, BUF** out_plain)
{
	bool res = false;

	if (out_plain != NULL)
	{
		*out_plain = NULL;

		if (in_cipher_text != NULL && in_cipher_text_len > 0)
		{
			DATA_BLOB in_blob = { 0 };
			DATA_BLOB out_blob = { 0 };
			DATA_BLOB entropy = { 0 };

			in_blob.cbData = in_cipher_text_len;
			in_blob.pbData = (BYTE*)in_cipher_text;

			entropy.cbData = (DWORD)sizeof(OIDC_ENTROPY_STR) - 1;
			entropy.pbData = (BYTE*)OIDC_ENTROPY_STR;

			if (CryptUnprotectData(&in_blob, NULL, &entropy, NULL, NULL, 0, &out_blob))
			{
				BUF* buf = NewBuf();
				if (buf != NULL)
				{
					WriteBuf(buf, out_blob.pbData, out_blob.cbData);
					*out_plain = buf;
					res = true;
				}
				LocalFree(out_blob.pbData);
			}
		}
	}

	return res;
}

// On-disk plaintext record before DPAPI: [u32 version][u64 expires_at][u32 token_len][token bytes]
// All fields are little-endian on Windows/MSVC.
#pragma pack(push, 1)
struct OIDC_REFRESH_REC_WIRE
{
	UINT   Version;
	UINT64 ExpiresAt;
	UINT   TokenLen;
};
#pragma pack(pop)

static bool OidcSerializeRecord(const char* token, UINT64 exp, BUF** out_plain)
{
	bool res = false;

	if (out_plain != NULL && token != NULL)
	{
		*out_plain = NULL;

		do
		{
			UINT token_len = (UINT)StrLen((char*)token);
			struct OIDC_REFRESH_REC_WIRE hdr;
			hdr.Version = 1;
			hdr.ExpiresAt = exp;
			hdr.TokenLen = token_len;

			BUF* buf = NewBuf();
			if (buf == NULL)
			{
				break;
			}

			WriteBuf(buf, &hdr, (UINT)sizeof(hdr));
			if (token_len > 0)
			{
				WriteBuf(buf, token, token_len);
			}

			*out_plain = buf;
			res = true;
		} while (0);
	}

	return res;
}

static bool OidcDeserializeRecord(const void* plain_text, UINT plain_text_len, char** out_token, UINT64* out_exp)
{
	bool res = false;

	if (out_token != NULL && out_exp != NULL && plain_text != NULL && plain_text_len >= (UINT)sizeof(struct OIDC_REFRESH_REC_WIRE))
	{
		*out_token = NULL;
		*out_exp = 0;

		do
		{
			const UCHAR* p_plain_text = (const UCHAR*)plain_text;
			const struct OIDC_REFRESH_REC_WIRE* hdr = (const struct OIDC_REFRESH_REC_WIRE*)p_plain_text;

			if (hdr->Version != 1)
			{
				break;
			}

			if ((UINT)sizeof(*hdr) + hdr->TokenLen > plain_text_len)
			{
				break;
			}

			const char* token_offset = (const char*)(p_plain_text + sizeof(*hdr));
			char* token = (char*)ZeroMalloc(hdr->TokenLen + 1);
			if (token == NULL)
			{
				break;
			}

			Copy(token, (void*)token_offset, hdr->TokenLen);
			token[hdr->TokenLen] = 0;

			*out_token = token;
			*out_exp = hdr->ExpiresAt;
			res = true;
		} while (0);
	}

	return res;
}

static bool OidcBuildPathWin(const char* key_id, char* out_path, UINT out_path_sz)
{
	bool res = false;

	if (IsEmptyStr((char*)key_id) == false && out_path != NULL && out_path_sz > 0)
	{
		out_path[0] = 0;

		char dir[MAX_PATH];
		if (OidcGetStoreDirWin(dir, sizeof(dir)))
		{
			Format(out_path, out_path_sz, "%s%s.bin", dir, key_id);
			res = (IsEmptyStr(out_path) == false);
		}
	}

	return res;
}

/* =========================
   Public API (Windows)
   ========================= */

OIDC_STATUS OidcStoreRefreshSave(const OIDC_CONFIG* cfg, const char* subject, const char* refresh_token, UINT64 expires_at_ms)
{
	OIDC_STATUS res = OIDC_ERR_INTERNAL;

	if (cfg != NULL && IsEmptyStr((char*)refresh_token) == false)
	{
		char key_id[128];            // hex(SHA-256) fits in 65 bytes; leave headroom
		char path[MAX_PATH * 2];

		if (OidcBuildKeyId(cfg, subject, key_id, (UINT)sizeof(key_id)) &&
			OidcBuildPathWin(key_id, path, (UINT)sizeof(path)))
		{
			BUF* plain = NULL;
			BUF* prot = NULL;

			if (OidcSerializeRecord(refresh_token, expires_at_ms, &plain) &&
				plain != NULL &&
				OidcDpapiProtect(plain->Buf, plain->Size, &prot) &&
				prot != NULL)
			{
				IO* io = FileCreate(path);
				if (io != NULL)
				{
					FileWrite(io, prot->Buf, prot->Size);
					FileClose(io);
					res = OIDC_OK;
				}
			}

			if (prot != NULL)
			{
				FreeBuf(prot);
				prot = NULL;
			}

			if (plain != NULL)
			{
				if (plain->Buf != NULL && plain->Size != 0)
				{
					SecureZero(plain->Buf, plain->Size);
				}
				FreeBuf(plain);
				plain = NULL;
			}
		}
	}

	return res;
}

OIDC_STATUS OidcStoreRefreshLoad(const OIDC_CONFIG* cfg, const char* subject, char** out_refresh_token, UINT64* out_expires_at_ms)
{
	OIDC_STATUS res = OIDC_ERR_INTERNAL;

	if (out_refresh_token != NULL)
	{
		*out_refresh_token = NULL;
	}

	if (out_expires_at_ms != NULL)
	{
		*out_expires_at_ms = 0;
	}

	if (cfg != NULL && out_refresh_token != NULL && out_expires_at_ms != NULL)
	{
		char key_id[128];
		char path[MAX_PATH * 2];

		if (OidcBuildKeyId(cfg, subject, key_id, (UINT)sizeof(key_id)) &&
			OidcBuildPathWin(key_id, path, (UINT)sizeof(path)))
		{
			IO* io = FileOpen(path, false);
			if (io == NULL)
			{
				res = OIDC_ERR_STORAGE_NOT_FOUND;
			}
			else
			{
				UINT total = FileSize(io);

				if (total == 0)
				{
					FileClose(io);
					io = NULL;
					res = OIDC_ERR_INTERNAL;
				}
				else
				{
					void* ciph = Malloc(total);

					if (FileRead(io, ciph, total) == false)
					{
						Free(ciph);
						ciph = NULL;
						FileClose(io);
						io = NULL;
						res = OIDC_ERR_INTERNAL;
					}
					else
					{
						FileClose(io);
						io = NULL;

						BUF* plain = NULL;

						if (OidcDpapiUnprotect(ciph, total, &plain) && plain != NULL)
						{
							char* token = NULL;
							UINT64 exp = 0;

							if (OidcDeserializeRecord(plain->Buf, plain->Size, &token, &exp))
							{
								*out_refresh_token = token;
								*out_expires_at_ms = exp;
								res = OIDC_OK;
							}
							else
							{
								res = OIDC_ERR_INTERNAL;
							}

							if (plain->Buf != NULL && plain->Size != 0)
							{
								SecureZero(plain->Buf, plain->Size);
							}

							FreeBuf(plain);
							plain = NULL;
						}
						else
						{
							res = OIDC_ERR_INTERNAL;
						}

						Free(ciph);
						ciph = NULL;
					}
				}
			}
		}
	}

	return res;
}


OIDC_STATUS OidcStoreRefreshClear(const OIDC_CONFIG* cfg, const char* subject)
{
	OIDC_STATUS res = OIDC_ERR_INTERNAL;

	if (cfg != NULL)
	{
		char key_id[128];
		char path[MAX_PATH * 2];

		if (OidcBuildKeyId(cfg, subject, key_id, (UINT)sizeof(key_id)) &&
			OidcBuildPathWin(key_id, path, (UINT)sizeof(path)))
		{
			if (FileDelete(path))
			{
				res = OIDC_OK;
			}
			else
			{
				res = OIDC_ERR_STORAGE_NOT_FOUND;
			}
		}
	}

	return res;
}
