// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module

// OidcJwt.h
// Simple utility functions for parsing the id_token (JWT) to extract username/email.

#ifndef OIDC_JWT_H
#define OIDC_JWT_H

#include "Mayaqua/Mayaqua.h"

#ifdef __cplusplus
extern "C" {
#endif

    bool OidcJwtGetUsernameFromIdToken(const char* jwt, char* out_username, UINT out_username_size);

#ifdef __cplusplus
}
#endif

#endif /* OIDC_JWT_H */