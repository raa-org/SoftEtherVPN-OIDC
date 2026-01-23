// OidcEmbededViewWin32.cpp
// Windows-only embedded WebView2 host (separate from system-browser logic).
// - Dynamic load of WebView2Loader.dll
// - Dedicated STA UI thread with message loop
// - Creates a window, initializes WebView2, navigates to URL
// - Returns from Open() once window is ready (shown)
//
// Build notes:
//   * Requires C++ (WRL). Include path must have WebView2 headers.
//   * Link with: user32.lib, ole32.lib, gdi32.lib, shlwapi.lib (typical).
//   * No link-time dependency on WebView2Loader.lib; we LoadLibrary at runtime.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include <wchar.h>
#include <shlwapi.h>

#include <shlobj.h>   // SHGetKnownFolderPath, SHCreateDirectoryExW
#include <strsafe.h>  // StringCchPrintfW

#include "OidcEmbededViewWin32.h"

// WRL + WebView2
#include <wrl.h>
#include <WebView2.h>
using Microsoft::WRL::ComPtr;

#ifndef _countof
#define _countof(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define WM_OIDC_NAVIGATE (WM_APP + 101)

const int g_suggestedWebViewWidth = 1024;
const int g_suggestedWebViewHeight = 768;

const wchar_t* g_webviewClassName = L"SoftEtherOidcWebView";

// ---------- Globals (UI thread state) ----------

static HANDLE g_uiThread = NULL;
static DWORD g_uiThreadId = 0;
static HANDLE g_evtStop = NULL;
static HANDLE g_evtReady = NULL;
static HANDLE g_evtClosed = NULL;

// 0 = pending, 1 = initialized (WebView created and Navigate issued), -1 = initialization failed
typedef enum
{ 
    INIT_PENDING = 0,
    INIT_OK = 1,
    INIT_FAIL = -1
}
INIT_WEB_VIEW_STATUS;

static volatile LONG g_initWebViewStatus = INIT_PENDING;

static HWND   g_hwnd = NULL;

static wchar_t g_navUrl[2048];
static wchar_t g_userDataFolder[MAX_PATH * 4] = { 0 }; // custom UDF for this WebView session
static char g_activeAccountKeyA[129] = { 0 }; // 64 (sha256 hex) or 128 (sha512 hex) + '\0'

static HMODULE g_webviewLoader = NULL; // Keep loaded while WebView lives

static ComPtr<ICoreWebView2Controller> g_webviewController;
static ComPtr<ICoreWebView2>           g_webview;

// ---------- Forward declarations ----------
static DWORD  WINAPI UiThreadProc(LPVOID param);
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
static BOOL RegisterWebViewWndClassIfNeeded(HINSTANCE hinst);
static void   ResizeWebViewToClient(void);
static HRESULT InitWebView2(HWND hwnd);
static void signalWebViewInitStatus(INIT_WEB_VIEW_STATUS status);

static int OidcEmbededView_OpenInternal(const char* url, void* parent_hwnd, unsigned int timeout_ms);
static BOOL IsSafeAccountKeyA(const char* s);
static BOOL GetUdfPathForAccountKeyA(const char* account_key, wchar_t* outPath, size_t outCount);
static BOOL EnsureDirectoryExistsW(const wchar_t* dir);
static BOOL DeleteDirectoryTreeW(const wchar_t* dir);

// ---------- Public API ----------

int OidcEmbededView_IsSupported(void)
{
    int ok = 0;

    HMODULE h = LoadLibraryW(L"WebView2Loader.dll");
    if (h != NULL)
    {
        FARPROC p = GetProcAddress(h, "CreateCoreWebView2EnvironmentWithOptions");
        if (p != NULL)
        {
            ok = 1;
        }
        FreeLibrary(h);
    }

    return ok;
}

int OidcEmbededView_Open(const char* url, void* parent_hwnd, unsigned int timeout_ms)
{
    // Default Open => no custom UDF
    g_userDataFolder[0] = 0;
    g_activeAccountKeyA[0] = 0;

    return OidcEmbededView_OpenInternal(url, parent_hwnd, timeout_ms);
}

int OidcEmbededView_OpenWithAccountKey(const char* url, const char* account_key, void* parent_hwnd, unsigned int timeout_ms)
{
    if (OidcEmbededView_IsOpen())
        return 0;

    g_userDataFolder[0] = 0;
    g_activeAccountKeyA[0] = 0;

    if (!GetUdfPathForAccountKeyA(account_key, g_userDataFolder, _countof(g_userDataFolder)))
        return 0;

    if (!EnsureDirectoryExistsW(g_userDataFolder))
    {
        g_userDataFolder[0] = 0;
        return 0;
    }

    strncpy_s(g_activeAccountKeyA, sizeof(g_activeAccountKeyA), account_key, _TRUNCATE);

    int ok = OidcEmbededView_OpenInternal(url, parent_hwnd, timeout_ms);
    if (!ok)
    {
        g_activeAccountKeyA[0] = 0;
        g_userDataFolder[0] = 0;
    }
    return ok;
}

void OidcEmbededView_Close(void)
{
    OidcEmbededView_RequestClose();

    if (g_uiThreadId != 0 && GetCurrentThreadId() == g_uiThreadId)
    {
        return;
    }

    if (g_evtClosed != NULL)
    {
        (void)WaitForSingleObject(g_evtClosed, 5000);
    }

    if (g_uiThread != NULL)
    {
        (void)WaitForSingleObject(g_uiThread, 5000);
        CloseHandle(g_uiThread);
        g_uiThread = NULL;
    }

    if (g_evtReady != NULL)
    {
        CloseHandle(g_evtReady);
        g_evtReady = NULL;
    }
    if (g_evtStop != NULL)
    {
        CloseHandle(g_evtStop);
        g_evtStop = NULL;
    }
    if (g_evtClosed != NULL)
    {
        CloseHandle(g_evtClosed);
        g_evtClosed = NULL;
    }

    g_activeAccountKeyA[0] = 0;
    g_userDataFolder[0] = 0;
}

void OidcEmbededView_RequestClose(void)
{
    if (g_hwnd != NULL)
        PostMessageW(g_hwnd, WM_CLOSE, 0, 0);

    if (g_evtStop != NULL)
        SetEvent(g_evtStop);
}

int OidcEmbededView_Navigate(const char* url)
{
    if (url == NULL || url[0] == '\0')
        return 0;

    if (g_hwnd == NULL || !OidcEmbededView_IsOpen())
        return 0;

    int wlen = MultiByteToWideChar(CP_UTF8, 0, url, -1, NULL, 0);
    if (wlen <= 0)
        return 0;

    wchar_t* wurl = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, wlen * sizeof(wchar_t));
    if (wurl == NULL)
        return 0;

    MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, wlen);

    if (!PostMessageW(g_hwnd, WM_OIDC_NAVIGATE, 0, (LPARAM)wurl))
    {
        HeapFree(GetProcessHeap(), 0, wurl);
        return 0;
    }

    return 1;
}

BOOL OidcEmbededView_IsOpen(void)
{
    BOOL isOpen = FALSE;
    if (g_uiThread != NULL)
    {
        DWORD wr = WaitForSingleObject(g_uiThread, 0);
        isOpen = (wr == WAIT_TIMEOUT) ? TRUE : FALSE; // running if not signaled
    }
    return isOpen;
}

// Returns: 1 = closed, 0 = still open, -1 = error/unknown
int OidcEmbededView_WaitClosed(unsigned int timeout_ms)
{
    if (g_uiThread == NULL)
        return 1;

    int isClosed = -1;

    // Prefer the WM_DESTROY signal; fall back to the thread handle.
    HANDLE h = (g_evtClosed != NULL) ? g_evtClosed : g_uiThread;
    DWORD wr = WaitForSingleObject(h, timeout_ms);
    if (wr == WAIT_OBJECT_0)
    {
        isClosed = 1;
    }
    else if (wr == WAIT_TIMEOUT)
    {
        isClosed = 0;
    }

    return isClosed;
}

int OidcEmbededView_PurgeAccountData(const char* account_key, unsigned int timeout_ms)
{
    if (!IsSafeAccountKeyA(account_key))
        return 0;

    wchar_t udf[MAX_PATH * 4] = { 0 };
    if (!GetUdfPathForAccountKeyA(account_key, udf, _countof(udf)))
        return 0;

    // Close only if the currently open WebView belongs to the same account_key
    if (OidcEmbededView_IsOpen() && _stricmp(g_activeAccountKeyA, account_key) == 0)
    {
        OidcEmbededView_Close();
        // Close() should already clear these, but keep best-effort:
        g_activeAccountKeyA[0] = 0;
        g_userDataFolder[0] = 0;
    }

    ULONGLONG  deadline = GetTickCount64() + (timeout_ms ? timeout_ms : 8000);

    for (;;)
    {
        if (DeleteDirectoryTreeW(udf))
            return 1;

        if (GetTickCount64() >= deadline)
            break;

        Sleep(150);
    }

    return 0;
}

// ---------- UI Thread ----------

static DWORD WINAPI UiThreadProc(LPVOID param)
{
    HWND parent = (HWND)param;

    bool isWindowClassRegistered = false;

    bool initSucceeded = SUCCEEDED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED));
    if (initSucceeded)
    {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

        HINSTANCE hinst = GetModuleHandleW(NULL);
        isWindowClassRegistered = RegisterWebViewWndClassIfNeeded(hinst);

        if (isWindowClassRegistered)
        {
            DWORD style = WS_OVERLAPPEDWINDOW;
            DWORD exstyle = WS_EX_APPWINDOW;

            UINT dpi = GetDpiForSystem();
            RECT rc = { 0, 0, MulDiv(g_suggestedWebViewWidth, dpi, 96), MulDiv(g_suggestedWebViewHeight, dpi, 96) };
            AdjustWindowRectEx(&rc, style, FALSE, exstyle);

            int width = rc.right - rc.left;
            int height = rc.bottom - rc.top;
            g_hwnd = CreateWindowExW(exstyle, g_webviewClassName, L"Sign in", style, CW_USEDEFAULT, CW_USEDEFAULT, width, height, parent, NULL, hinst, NULL);
            if (g_hwnd != NULL)
            {
                ShowWindow(g_hwnd, SW_SHOW);
                UpdateWindow(g_hwnd);

                // Initialize WebView2 (async)
                if (FAILED(InitWebView2(g_hwnd)))
                {
                    signalWebViewInitStatus(INIT_FAIL);
                }

                // Message loop with stop-event pumping
                HANDLE waitHandles[1];
                waitHandles[0] = g_evtStop;

                BOOL running = TRUE;
                while (running)
                {
                    DWORD wr = MsgWaitForMultipleObjects(1, waitHandles, FALSE, 50, QS_ALLINPUT);

                    if (wr == WAIT_OBJECT_0)
                    {
                        running = FALSE;
                    }
                    else
                    {
                        MSG msg;
                        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
                        {
                            if (msg.message == WM_QUIT)
                            {
                                running = FALSE;
                                break;
                            }
                            TranslateMessage(&msg);
                            DispatchMessageW(&msg);
                        }
                    }
                }

                // Teardown
                if (g_webview)
                {
                    g_webview.Reset();
                }
                if (g_webviewController)
                {
                    g_webviewController->Close();
                    g_webviewController.Reset();
                }

                if (g_hwnd != NULL)
                {
                    DestroyWindow(g_hwnd);
                    g_hwnd = NULL;
                }

                if (g_webviewLoader != NULL)
                {
                    FreeLibrary(g_webviewLoader);
                    g_webviewLoader = NULL;
                }
            }
        }

        CoUninitialize();
    }

    if (!initSucceeded || !isWindowClassRegistered)
    {
        signalWebViewInitStatus(INIT_FAIL);
    }

    g_uiThreadId = 0;

    return 0;
}

// ---------- Window + WebView helpers ----------

static int OidcEmbededView_OpenInternal(const char* url, void* parent_hwnd, unsigned int timeout_ms)
{
    int ok = 0;

    if (url != NULL && url[0] != '\0')
    {
        // Convert URL to wide
        int wlen = MultiByteToWideChar(CP_UTF8, 0, url, -1, NULL, 0);
        if (wlen > 0 && wlen <= (int)_countof(g_navUrl))
        {
            MultiByteToWideChar(CP_UTF8, 0, url, -1, g_navUrl, (int)_countof(g_navUrl));

            if (g_evtStop == NULL)
            {
                g_evtStop = CreateEventW(NULL, TRUE, FALSE, NULL);
            }
            else
            {
                ResetEvent(g_evtStop);
            }

            if (g_evtReady == NULL)
            {
                g_evtReady = CreateEventW(NULL, TRUE, FALSE, NULL);
            }
            else
            {
                ResetEvent(g_evtReady);
            }

            if (g_evtClosed == NULL)
            {
                g_evtClosed = CreateEventW(NULL, TRUE, FALSE, NULL);
            }
            else
            {
                ResetEvent(g_evtClosed);
            }

            if (g_evtStop != NULL && g_evtReady != NULL && g_evtClosed != NULL)
            {
                InterlockedExchange(&g_initWebViewStatus, INIT_PENDING);

                DWORD tid = 0;
                g_uiThread = CreateThread(NULL, 0, UiThreadProc, parent_hwnd, 0, &tid);
                if (g_uiThread != NULL)
                {
                    g_uiThreadId = tid;

                    HANDLE waitOn[2] = { g_evtReady, g_uiThread };
                    DWORD wait = timeout_ms ? timeout_ms : 10000;
                    DWORD wr = WaitForMultipleObjects(2, waitOn, FALSE, wait);

                    if (wr == WAIT_OBJECT_0) // g_evtReady
                    {
                        LONG init_status = InterlockedCompareExchange(&g_initWebViewStatus, 0, 0);
                        ok = (init_status == INIT_OK) ? 1 : 0;
                        if (!ok)
                        {
                            // clean up a UI thread that never got fully ready
                            OidcEmbededView_Close();
                        }
                    }
                    else if (wr == WAIT_OBJECT_0 + 1) // thread exited early
                    {
                        ok = 0;
                    }
                    else // WAIT_TIMEOUT or WAIT_FAILED
                    {
                        ok = 0;
                        OidcEmbededView_Close(); // graceful shutdown
                    }
                }
            }
        }
    }

    return ok;
}

static void signalWebViewInitStatus(INIT_WEB_VIEW_STATUS status)
{
    if (g_evtReady == NULL)
        return;

    LONG prev = InterlockedCompareExchange(&g_initWebViewStatus, status, INIT_PENDING);
    if (prev == INIT_PENDING)
    {
        SetEvent(g_evtReady);
    }
}

static BOOL RegisterWebViewWndClassIfNeeded(HINSTANCE hinst)
{
    BOOL isRegistered = FALSE;

    WNDCLASSEXW wci;
    ZeroMemory(&wci, sizeof(wci));
    wci.cbSize = sizeof(wci);

    isRegistered = GetClassInfoExW(hinst, g_webviewClassName, &wci);
    if (!isRegistered)
    {
        WNDCLASSW wc = {};
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WndProc;
        wc.hInstance = hinst;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = g_webviewClassName;

        ATOM a = RegisterClassW(&wc);

        isRegistered = (a != 0 || GetLastError() == ERROR_CLASS_ALREADY_EXISTS);
    }

    return isRegistered;
}

static void ResizeWebViewToClient(void)
{
    if (g_webviewController)
    {
        RECT rc;
        GetClientRect(g_hwnd, &rc);
        g_webviewController->put_Bounds(rc);
    }
    return;
}

static void UpdateMinMaxInfo(MINMAXINFO* minmaxInfo)
{
    UINT dpi = (g_hwnd != NULL) ? GetDpiForWindow(g_hwnd) : GetDpiForSystem();

    minmaxInfo->ptMinTrackSize.x = MulDiv(g_suggestedWebViewWidth, dpi, 96);  // min client width target
    minmaxInfo->ptMinTrackSize.y = MulDiv(g_suggestedWebViewHeight, dpi, 96);  // min client height target
    return;
}

static void ResizeWebView(HWND hwnd)
{
    if (g_webviewController)
    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        g_webviewController->put_Bounds(rc);
    }
    return;
}

static void UpdateDpi(HWND hWnd, UINT dpi, RECT* suggestedRect)
{
    SetWindowPos(hWnd, nullptr,
        suggestedRect->left, suggestedRect->top,
        suggestedRect->right - suggestedRect->left,
        suggestedRect->bottom - suggestedRect->top,
        SWP_NOZORDER | SWP_NOACTIVATE);

    if (g_webviewController)
    {
        ICoreWebView2Controller3* ctl3 = NULL;
        if (SUCCEEDED(g_webviewController->QueryInterface(IID_PPV_ARGS(&ctl3))) && ctl3)
        {
            ctl3->put_RasterizationScale(dpi / 96.0);
            ctl3->Release();
        }
        ResizeWebViewToClient();
    }
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_GETMINMAXINFO:
        UpdateMinMaxInfo((MINMAXINFO*)lParam);
        break;

    case WM_SIZE:
        ResizeWebViewToClient();
        break;

    case WM_DPICHANGED:
        UpdateDpi(hWnd, HIWORD(wParam), reinterpret_cast<RECT*>(lParam));
        break;

    case WM_OIDC_NAVIGATE:
    {
        wchar_t* wurl = (wchar_t*)lParam;
        if (g_webview && wurl)
            g_webview->Navigate(wurl);
        if (wurl)
            HeapFree(GetProcessHeap(), 0, wurl);
        break;
    }   

    case WM_CLOSE:
        DestroyWindow(hWnd);
        break;

    case WM_NCDESTROY:
        g_hwnd = NULL;
        break;

    case WM_DESTROY:
    {
        if (g_evtClosed)
        {
            SetEvent(g_evtClosed);
        }
        PostQuitMessage(0);
        break;
    }

    default:
        break;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static HRESULT InitWebView2(HWND hwnd)
{
    if (g_webviewLoader == NULL)
    {
        g_webviewLoader = LoadLibraryW(L"WebView2Loader.dll");
        if (g_webviewLoader == NULL)
        {
            signalWebViewInitStatus(INIT_FAIL);
            return E_FAIL;
        }
    }

    typedef HRESULT(STDAPICALLTYPE* PFN_CreateCoreWebView2EnvironmentWithOptions)(PCWSTR, PCWSTR, ICoreWebView2EnvironmentOptions*, ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*);

    PFN_CreateCoreWebView2EnvironmentWithOptions pCreateEnv = (PFN_CreateCoreWebView2EnvironmentWithOptions)GetProcAddress(g_webviewLoader, "CreateCoreWebView2EnvironmentWithOptions");

    if (pCreateEnv == NULL)
    {
        signalWebViewInitStatus(INIT_FAIL);
        return E_FAIL;
    }

    PCWSTR udf = (g_userDataFolder[0] ? g_userDataFolder : NULL);

    // Create environment, then controller bound to our HWND
    HRESULT hr = pCreateEnv(
        NULL,   // browserExecutableFolder
        udf,    // userDataFolder
        NULL,   // environmentOptions
        Microsoft::WRL::Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [hwnd](HRESULT result, ICoreWebView2Environment* env) -> HRESULT
            {
                if (FAILED(result) || env == nullptr)
                {
                    signalWebViewInitStatus(INIT_FAIL);
                    return E_FAIL;
                }

                return env->CreateCoreWebView2Controller(
                    hwnd,
                    Microsoft::WRL::Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [](HRESULT result, ICoreWebView2Controller* controller) -> HRESULT
                        {
                            if (FAILED(result) || controller == nullptr)
                            {
                                signalWebViewInitStatus(INIT_FAIL);
                                return E_FAIL;
                            }

                            g_webviewController = controller;

                            HRESULT hr2 = g_webviewController->get_CoreWebView2(&g_webview);
                            if (FAILED(hr2) || !g_webview)
                            {
                                signalWebViewInitStatus(INIT_FAIL);
                                return E_FAIL;
                            }

                            ICoreWebView2Controller3* ctl3 = nullptr;
                            if (SUCCEEDED(controller->QueryInterface(IID_PPV_ARGS(&ctl3))) && ctl3) {
                                // Per-monitor DPI -> scale = dpi / 96
                                const UINT dpi = GetDpiForWindow(g_hwnd);
                                const double scale = dpi / 96.0;
                                ctl3->put_RasterizationScale(scale);
                                ctl3->put_ShouldDetectMonitorScaleChanges(TRUE);
                                ctl3->put_BoundsMode(COREWEBVIEW2_BOUNDS_MODE_USE_RASTERIZATION_SCALE);
                                ctl3->Release();
                            }

                            ResizeWebViewToClient();

                            controller->put_ZoomFactor(1.0);

                            g_webview->Navigate(g_navUrl);

                            signalWebViewInitStatus(INIT_OK);
                            return S_OK;
                        }
                    ).Get()
                );
            }
        ).Get()
    );

    return hr;
}

static BOOL IsSafeAccountKeyA(const char* s)
{
    if (s == NULL)
    {
        return FALSE;
    }

    size_t n = strlen(s);
    if (n != 64 && n != 128)
    {
        return FALSE;
    }

    for (size_t i = 0; i < n; ++i)
    {
        char c = s[i];
        if (!((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F')))
        {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL GetUdfPathForAccountKeyA(const char* account_key, wchar_t* outPath, size_t outCount)
{
    if (!IsSafeAccountKeyA(account_key) || outPath == NULL || outCount == 0)
        return FALSE;

    // account_key -> wide
    wchar_t keyW[256] = { 0 };
    int wlen = MultiByteToWideChar(CP_UTF8, 0, account_key, -1, keyW, (int)_countof(keyW));
    if (wlen <= 0)
        return FALSE;

    PWSTR localAppData = NULL;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &localAppData);
    if (FAILED(hr) || localAppData == NULL)
        return FALSE;

    // %LOCALAPPDATA%\SoftEtherVPN\webview2\udf\<account_key>
    hr = StringCchPrintfW(outPath, outCount, L"%s\\SoftEtherVPN\\webview2\\udf\\%s", localAppData, keyW);
    CoTaskMemFree(localAppData);

    return SUCCEEDED(hr) ? TRUE : FALSE;
}

static BOOL EnsureDirectoryExistsW(const wchar_t* dir)
{
    if (dir == NULL || dir[0] == 0)
        return FALSE;

    // If already exists and is a directory => ok
    DWORD attrs = GetFileAttributesW(dir);
    if (attrs != INVALID_FILE_ATTRIBUTES)
    {
        return (attrs & FILE_ATTRIBUTE_DIRECTORY) ? TRUE : FALSE;
    }

    // Create full path
    int r = SHCreateDirectoryExW(NULL, dir, NULL);
    if (r != ERROR_SUCCESS && r != ERROR_ALREADY_EXISTS && r != ERROR_FILE_EXISTS)
        return FALSE;

    // Verify it's really a directory
    attrs = GetFileAttributesW(dir);
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return FALSE;

    return (attrs & FILE_ATTRIBUTE_DIRECTORY) ? TRUE : FALSE;
}

static BOOL DeleteDirectoryTreeW(const wchar_t* dir)
{
    if (dir == NULL || dir[0] == 0)
        return FALSE;

    DWORD attrs = GetFileAttributesW(dir);
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        // Already gone => success
        DWORD err = GetLastError();
        return (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) ? TRUE : FALSE;
    }

    // dir\*
    wchar_t pattern[MAX_PATH * 4] = { 0 };
    if (FAILED(StringCchPrintfW(pattern, _countof(pattern), L"%s\\*", dir)))
        return FALSE;

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        // Might be empty or access issue. Try remove dir anyway.
        SetFileAttributesW(dir, FILE_ATTRIBUTE_NORMAL);
        if (RemoveDirectoryW(dir))
            return TRUE;

        return FALSE;
    }

    BOOL ok = TRUE;

    do
    {
        const wchar_t* name = fd.cFileName;
        if (wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0)
            continue;

        wchar_t child[MAX_PATH * 4] = { 0 };
        if (FAILED(StringCchPrintfW(child, _countof(child), L"%s\\%s", dir, name)))
        {
            ok = FALSE;
            break;
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            {
                // Do not follow junction/symlink; remove link itself
                SetFileAttributesW(child, FILE_ATTRIBUTE_NORMAL);
                if (!RemoveDirectoryW(child))
                    ok = FALSE;
            }
            else
            {
                if (!DeleteDirectoryTreeW(child))
                    ok = FALSE;
            }
        }
        else
        {
            // remove read-only etc
            SetFileAttributesW(child, FILE_ATTRIBUTE_NORMAL);
            if (!DeleteFileW(child))
            {
                // might be locked
                ok = FALSE;
            }
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);

    // remove the directory itself
    SetFileAttributesW(dir, FILE_ATTRIBUTE_NORMAL);
    if (!RemoveDirectoryW(dir))
    {
        DWORD err = GetLastError();
        if (!(err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND))
            ok = FALSE;
    }

    return ok;
}
