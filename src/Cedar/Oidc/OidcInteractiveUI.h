// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
//
// OidcInteractiveUI.h
// Cross-platform API: open system default browser to a given URL.

#ifndef OIDC_BROWSER_H
#define OIDC_BROWSER_H

// UI surface
typedef enum OIDC_UI_MODE {
	OIDC_UI_SYSTEM_BROWSER = 0,	// default browser
	OIDC_UI_EMBEDDED_VIEW = 1	// embedded (Windows: WebView2)
} OIDC_UI_MODE;

typedef struct OIDC_UI_OPTIONS {
	OIDC_UI_MODE Mode;
	UINT TimeoutMs;               // optional; 0 = library default
#ifdef OS_WIN32
	void* ParentHwnd;             // optional parent HWND (NULL => top-level window)
#endif
} OIDC_UI_OPTIONS;

#ifdef __cplusplus
extern "C" {
#endif

	/* Open the UI to show the given URL.
	   Returns 1 on success, 0 on failure (or unsupported mode on this platform).
	   Notes:
		 - SYSTEM_BROWSER: opens and returns immediately.
		 - WEBVIEW (Windows): creates a window, navigates to URL, and returns immediately.
		   Caller is expected to run its own loopback wait and then call OidcUiClose() when done.
	*/
	int OidcUiOpen(const char* url, const OIDC_UI_OPTIONS* opt);

	/* Close any UI opened via OidcUiOpen().
	   No-op for SYSTEM_BROWSER; closes the WebView window on Windows. */
	void OidcUiClose(void);

	/* 1 if UI window is open (only for embedded), 0 otherwise */
	int  OidcUiIsOpen(void);

	int OidcUiWaitClosed(unsigned int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* OIDC_BROWSER_H */
