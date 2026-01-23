// OidcEmbededViewWin32.h
// Windows-only WebView2 host for interactive OIDC flows.
// This module only manages an embedded WebView window (create, navigate, close).

#ifndef OIDC_EMBEDED_VIEW_WIN32_H
#define OIDC_EMBEDED_VIEW_WIN32_H

#ifdef __cplusplus
extern "C" {
#endif

	/* Returns 1 if WebView2Loader.dll can be loaded at runtime; 0 otherwise. */
	int OidcEmbededView_IsSupported(void);

	/* Creates a WebView2 window and navigates to the given URL.
	   - url: UTF-8 string. Must not be NULL or empty.
	   - parent_hwnd: optional HWND parent (pass NULL for top-level window).
	   - timeout_ms: optional wait for "ready" signal (window created). 0 => 10s default.
	   Returns 1 if the UI thread started and the window was shown; 0 on failure.
	   Note: This call returns immediately after the window is ready (not after page load). */
	int OidcEmbededView_Open(const char* url, void* parent_hwnd, unsigned int timeout_ms);

	/* Creates a WebView2 window and navigates to the given URL, using a per-account UDF.
	   - account_key: UTF-8 safe key (recommended: hex string). Used to build:
		 %LOCALAPPDATA%\SoftEtherVPN\webview2\udf\<account_key>
	   Returns 1 on success, 0 on failure. */
	int OidcEmbededView_OpenWithAccountKey(const char* url, const char* account_key, void* parent_hwnd, unsigned int timeout_ms);

	/* Closes the WebView window and stops the UI thread. Safe to call multiple times. */
	void OidcEmbededView_Close(void);
	void OidcEmbededView_RequestClose(void);

	/* Return 1 if WebView window/UI thread is alive, else 0 */
	int  OidcEmbededView_IsOpen(void);

	/* Wait for window to close.
	   return 1 = closed, 0 = timeout, -1 = error */
	int  OidcEmbededView_WaitClosed(unsigned int timeout_ms);

	/* Deletes per-account WebView2 user data folder:
	   %LOCALAPPDATA%\SoftEtherVPN\webview2\udf\<account_key>
	   If the WebView is currently open for this account_key, it will be closed first.
	   Returns 1 on success, 0 on failure. */
	int OidcEmbededView_PurgeAccountData(const char* account_key, unsigned int timeout_ms);

	int OidcEmbededView_Navigate(const char* url);

#ifdef __cplusplus
}
#endif

#endif /* OIDC_EMBEDED_VIEW_WIN32_H */
