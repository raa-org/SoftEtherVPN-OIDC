// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module

// OidcLog.h — common logging macros and helpers for OIDC

#pragma once

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Memory.h"

#ifndef OIDC_LOG
#define OIDC_LOG 1
#endif

// Optional ANSI color macros; by default empty
#ifndef OIDC__C_INFO
#define OIDC__C_INFO  ""
#endif

#ifndef OIDC__C_WARN
#define OIDC__C_WARN  ""
#endif

#ifndef OIDC__C_ERROR
#define OIDC__C_ERROR ""
#endif

#ifndef OIDC__C_RESET
#define OIDC__C_RESET ""
#endif

#if OIDC_LOG

// First argument of each call MUST be format string, like in Debug().
#define OIDC_LOG_INFO(...)  Debug("[OIDC]" OIDC__C_INFO  "[INFO]  "  OIDC__C_RESET __VA_ARGS__)
#define OIDC_LOG_WARN(...)  Debug("[OIDC]" OIDC__C_WARN  "[WARN]  "  OIDC__C_RESET __VA_ARGS__)
#define OIDC_LOG_ERROR(...) Debug("[OIDC]" OIDC__C_ERROR "[ERROR] "  OIDC__C_RESET __VA_ARGS__)

#else
#define OIDC_LOG_INFO(...)  ((void)0)
#define OIDC_LOG_WARN(...)  ((void)0)
#define OIDC_LOG_ERROR(...) ((void)0)
#endif

