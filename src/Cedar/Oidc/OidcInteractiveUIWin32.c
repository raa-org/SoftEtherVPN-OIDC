// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
//
// OidcInteractiveUIWin32.c
// Windows implementation: system default browser; WEBVIEW is a stub for now.

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Str.h"
#include "OidcInteractiveUI.h"
#include "OidcEmbededViewWin32.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>

static OIDC_UI_MODE g_last_mode = OIDC_UI_SYSTEM_BROWSER;

static int OpenSystemBrowserWin32(const char* url)
{
    int res = 0;

    if (url != NULL && url[0] != '\0')
    {
        /* Prefer ShellExecuteA for default URL handler */
        HINSTANCE h = ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);

        if ((INT_PTR)h > 32)
        {
            res = 1;
        }
        else
        {
            /* Fallback to CreateProcess with cmd.exe /c start */
            char cmd[2048];
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;

            _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, "cmd.exe /c start \"\" \"%s\"", url);

            ZeroMemory(&si, sizeof(si));
            si.cb = sizeof(si);
            ZeroMemory(&pi, sizeof(pi));

            if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                res = 1;
            }
        }
    }

    return res;
}

int OidcUiOpen(const char* url, const OIDC_UI_OPTIONS* opt)
{
    int res = 0;

    if (url != NULL && url[0] != '\0')
    {
        OIDC_UI_MODE mode = opt ? opt->Mode : OIDC_UI_SYSTEM_BROWSER;

        g_last_mode = mode;
       
        bool isEmbededViewImplmented = OidcEmbededView_IsSupported();
        if (isEmbededViewImplmented && mode == OIDC_UI_EMBEDDED_VIEW)
        {
            res = OidcEmbededView_Open(url, opt ? opt->ParentHwnd : NULL, opt ? opt->TimeoutMs : 0);
        }
        else
        {
            res = OpenSystemBrowserWin32(url);
        }
    }

    return res;
}

void OidcUiClose(void)
{
    if (g_last_mode == OIDC_UI_EMBEDDED_VIEW)
    {
        OidcEmbededView_Close();
    }   
}

int OidcUiIsOpen(void)
{
    int res = 0; // system browser: we can't track its lifetime

    if (g_last_mode == OIDC_UI_EMBEDDED_VIEW)
    {
        res = OidcEmbededView_IsOpen();
    }

    return res;
}

int OidcUiWaitClosed(unsigned int timeout_ms)
{
    int res = 0; // system browser: treat as "not closed within timeout"

    if (g_last_mode == OIDC_UI_EMBEDDED_VIEW)
    {
        res = OidcEmbededView_WaitClosed(timeout_ms);
    }

    return res;
}
