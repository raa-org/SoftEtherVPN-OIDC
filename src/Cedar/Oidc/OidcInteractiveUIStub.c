// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
//
// OidcInteractiveUIStub.c
// Non-Windows implementation: open default browser (best-effort) or stub.

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Str.h"
#include "OidcInteractiveUI.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int OpenDefaultBrowser(const char* url)
{
    int res = 0;

    if (url != NULL && url[0] != '\0')
    {
        /* Try macOS first */
        {
            char cmd[2048];
            int n = snprintf(cmd, sizeof(cmd), "open '%s' >/dev/null 2>&1 &", url);
            if (n > 0 && (size_t)n < sizeof(cmd))
            {
                int rc = system(cmd);
                if (rc == 0)
                {
                    res = 1;
                }
            }
        }

        /* Try Linux (xdg-open) if macOS attempt failed */
        if (res == 0)
        {
            char cmd[2048];
            int n = snprintf(cmd, sizeof(cmd), "xdg-open '%s' >/dev/null 2>&1 &", url);
            if (n > 0 && (size_t)n < sizeof(cmd))
            {
                int rc = system(cmd);
                if (rc == 0)
                {
                    res = 1;
                }
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
        /* Only SYSTEM_BROWSER is supported on non-Windows for now */
        OIDC_UI_MODE mode = OIDC_UI_SYSTEM_BROWSER;

        if (opt != NULL)
        {
            mode = opt->Mode;
        }

        if (mode == OIDC_UI_SYSTEM_BROWSER)
        {
            res = OpenDefaultBrowser(url);
        }
        else
        {
            /* WEBVIEW not supported on this platform */
            res = 0;
        }
    }

    return res;
}

void OidcUiClose(void)
{
    /* No-op: nothing to close on non-Windows in this stub. */
}

int OidcUiIsOpen(void)
{
    return 0;
}

int OidcUiWaitClosed(UINT timeout_ms)
{
    (void)timeout_ms;
    return 0;
}
