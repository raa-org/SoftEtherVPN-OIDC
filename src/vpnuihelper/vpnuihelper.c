// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module

// UI Helper for SoftEther VPN Client (Windows)
// -------------------------------------------
// This executable is a small Win32 tray helper that talks to the local
// SoftEther VPN client service and provides a minimal always-on UI:
//
//  - Creates a hidden top-level window and a notification-area (tray) icon.
//  - Shows connection status and a simple tooltip. When connected, the
//    helper tries to detect the public IPv4 address via api.ipify.org and
//    displays it in the tray tooltip.
//  - Exposes a context menu on right-click:
//      * Connect   – connect the first configured VPN account.
//      * Disconnect – disconnect all active VPN connections.
//      * Log out ->
//           Log out – clear stored OIDC tokens(refresh / id).
//           Log out and forget – clear tokens and browser sign - in data(WebView2 cookies / storage).
//      * Exit      – close the helper.
//
//  OIDC behaviour
//  --------------
//  - All OIDC logic (silent refresh, interactive sign-in, token storage) is
//    handled by the SoftEther VPN client service.
//  - The helper does NOT access OIDC tokens directly. Instead it:
//      * asks the service for the currently "logged in" OIDC user (if any)
//        via CcOidcGetLoggedInUser, in order to show "Log out (user)" in
//        the tray menu;
//      * requests a global OIDC logout via CcOidcLogoutAllAccounts, which
//        clears stored refresh tokens and id_tokens on the service side;
//      * triggers a connection for the first configured account via CcConnect.
//  - Non-OIDC accounts are unaffected by these commands; their authentication
//    is handled entirely by the service.
//
//  Limitations and assumptions
//  ---------------------------
//  - Windows-only helper; depends on Win32 APIs (tray icon, window messages,
//    IP Helper API, Winsock).
//  - Only one primary VPN account is used for the "Connect" command; this is
//    intentional and keeps the UX simple for end-users.
//  - Only OIDC-based accounts are touched for login / logout; non-OIDC auth
//    types are ignored by the helper.
//  - Public IP detection uses http://api.ipify.org (plain HTTP). No secrets
//    are sent to this service; it is used only to resolve the current public
//    IPv4 address. This can be switched to HTTPS in the future if desired.
//
//  This helper is intended to be a small, self-contained tray companion for
//  the SoftEther VPN client, focused on a single-account connect/disconnect
//  UX with OIDC status and logout delegated to the service.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

// Winsock2 must be included before windows.h so that _WINSOCK2API_ is defined
// and IP Helper API types like IP_ADAPTER_ADDRESSES are available.
#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <shellapi.h>
#include <string.h>
#include <stdio.h>
#include <iphlpapi.h>
#include <winver.h>
#include <stdbool.h>
#include <wchar.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Version.lib")

#include "resource.h"

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/HTTP.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Win32.h"
#include "Mayaqua/Tick64.h"   // Tick64(), TickHighres64(), Diff64(), ...

#include "Cedar/Cedar.h"
#include "Cedar/WinUi.h"
#include "Cedar/CM.h"
#include "Cedar/CMInner.h"
#include "Cedar/Client.h"
#include "Cedar/Connection.h"

#define PUBLIC_IP_REFRESH_INTERVAL_MS 60000ULL

#define WMAPP_TRAYICON (WM_APP + 1)
#define IDM_TRAY_EXIT           40000
#define IDM_TRAY_CONNECT        40001
#define IDM_TRAY_DISCONNECT     40002
#define IDM_TRAY_ABOUT          40003

#define IDM_TRAY_LOGOUT_MENU    40010   // "Log out ->" (only container)
#define IDM_TRAY_LOGOUT_TOKENS  40011   // "Log out" (clear tokens)
#define IDM_TRAY_LOGOUT_FORGET  40012   // "Log out and forget" (clear tokens & browser data)

typedef struct PUBLIC_IP_JOB
{
    char* dev_name;          // owned by worker
    HANDLE cancel_event;     // borrowed (global)
    LONG gen;                // generation
} PUBLIC_IP_JOB;

typedef enum {
    ACCOUNT_STATUS_UNKNOWN = 0,
    ACCOUNT_STATUS_DISCONNECTED,
    ACCOUNT_STATUS_CONNECTED,
} ACCOUNT_STATUS;

static wchar_t g_appTitle[256] = L"";
static wchar_t g_currentAccountName[MAX_ACCOUNT_NAME_LEN] = L"";

static HINSTANCE        g_hInst = NULL;
static HWND             g_hMainWnd = NULL;
static const UINT       HELPER_TIMER_ID = 1;

static REMOTE_CLIENT*   g_rc = NULL;
static bool g_lastConnected = false;
static bool g_trayAnimation = false;
static UINT g_trayCounter = 0;

static char g_publicIp[64] = { 0 };
static bool g_publicIpValid = false;
static bool g_publicIpInProgress = false;

static CRITICAL_SECTION g_publicIpLock;
static HANDLE g_publicIpThread = NULL;
static HANDLE g_publicIpCancelEvent = NULL;   // manual-reset event

static LONG g_publicIpGen = 0;                // generation counter
static LONG g_publicIpPendingGen = 0;

static char* g_publicIpPendingDevName = NULL; // owned by main thread, freed by main thread
static UINT64 g_publicIpNextRefreshTick = 0;

HANDLE TryExecUiHelperProcessHandle;
volatile bool TryExecUiHelperHalt;
EVENT* TryExecUiHelperHaltEvent;
THREAD* TryExecUiHelperThread;

static bool IsEmptyWStr(const wchar_t* s);

static BOOL HelperLoadSelfMetaStrings(void);
static void HelperSetCurrentAccount(const wchar_t* name);

void UiHelperInitTryToExecUiHelper();
void UiHelperFreeTryToExecUiHelper();
void UiHelperTryToExecUiHelperThread(THREAD* thread, void* param);
void UiHelperTryToExecUiHelper();
void* UiHelperExecUiHelperMain();

static bool HelperConnectToService(void);
static void HelperDisconnectFromService(void);

static void HelperResetPublicIpCache();
static bool HelperGetPublicIp(char* out_ip, UINT out_ip_size, HANDLE cancelEvent);
static void HelperRequestPublicIpJobRestart(const char* device_name);
static void HelperTryStartPendingPublicIpJob(void);
static DWORD WINAPI HelperPublicIpThreadProc(LPVOID param);
static void HelperMaybeSchedulePeriodicPublicIpRefresh(void);
static bool HelperIsCancelSignaled(HANDLE cancelEvent);

static LRESULT CALLBACK UiHelperWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
static BOOL UiHelperCreateMainWindow(void);
static BOOL UiHelperAddTrayIcon(void);
static void UiHelperRemoveTrayIcon(void);
static void UiHelperShowTrayMenu(HWND hWnd);
static void UiHelperUpdateTrayIcon(bool connected, const wchar_t* tooltip);

static void HelperShowAbout(HWND hWnd);
static BOOL GetSelfVersionStringW(const wchar_t* key, wchar_t* out, DWORD out_cch);
static BOOL GetServiceVersionStringW(const wchar_t* key, wchar_t* out, DWORD out_cch);
static BOOL GetFileVersionStringW(const wchar_t* path, const wchar_t* key, wchar_t* out, DWORD out_cch);
static void NormalizeVersionDotsInPlaceW(wchar_t* s, size_t cch);

static void HelperMain(void);

static bool HelperIsAnyConnected(void);
static bool HelperGetConnectedDeviceName(char* out_device_name, UINT out_device_name_size);
static ACCOUNT_STATUS HelperGetAccountStatus(const wchar_t* accountName);
static void HelperConnectFirstAccount(HWND hWnd);
static void HelperDisconnectActiveAccounts(HWND hWnd);

static bool HelperGetLoggedInOidcUser(wchar_t* out_user, UINT out_user_size);
static void HelperLogoutAllOidcAccounts(HWND hWnd);
static void HelperLogoutAllOidcAccountsAndForget(HWND hWnd);

static bool IsEmptyWStr(const wchar_t* s)
{
    return (s == NULL || s[0] == 0);
}

static BOOL HelperLoadSelfMetaStrings(void)
{
    if (!GetSelfVersionStringW(L"ProductName", g_appTitle, _countof(g_appTitle)))
        return FALSE;

    return TRUE;
}

static void HelperSetCurrentAccount(const wchar_t* name)
{
    if (name == NULL || name[0] == 0)
        g_currentAccountName[0] = 0;
    else
        lstrcpynW(g_currentAccountName, name, _countof(g_currentAccountName));
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    InitProcessCallOnce();

#if defined(_DEBUG) || defined(DEBUG)
    InitMayaqua(false, true, 0, NULL);
#else
    InitMayaqua(false, false, 0, NULL);
#endif
    InitCedar();

    if (!HelperLoadSelfMetaStrings())
    {
        MessageBoxW(NULL,
            L"Missing VERSIONINFO strings (FileDescription/ProductName) in vpnuihelper.exe.",
            L"vpnuihelper",
            MB_OK | MB_ICONERROR);
        return 1;
    }

    // Initialize WinUi (icons, string resources, etc.)
    InitWinUi(g_appTitle, NULL, 0);

    UiHelperInitTryToExecUiHelper();

    if (!CnIsCnServiceReady())
    {
        CnWaitForCnServiceReady();
    }

    g_hInst = hInstance;

    HelperMain();

    UiHelperFreeTryToExecUiHelper();
    FreeCedar();
    FreeMayaqua();

    return 0;
}

static void HelperMain(void)
{
    g_hInst = GetModuleHandleW(NULL);

    InitializeCriticalSection(&g_publicIpLock);

    g_publicIpCancelEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_publicIpCancelEvent == NULL)
    {
        MessageBoxW(NULL, L"Failed to create cancel event.", L"vpnuihelper", MB_OK | MB_ICONERROR);
        DeleteCriticalSection(&g_publicIpLock);
        return;
    }
    HelperResetPublicIpCache();

    if (!UiHelperCreateMainWindow())
    {
        MessageBoxW(NULL, L"Failed to create helper window.", L"vpnuihelper", MB_OK | MB_ICONERROR);
        CloseHandle(g_publicIpCancelEvent);
        g_publicIpCancelEvent = NULL;
        DeleteCriticalSection(&g_publicIpLock);
        return;
    }

    if (!UiHelperAddTrayIcon())
    {
        MessageBoxW(NULL, L"Failed to add tray icon.", L"vpnuihelper", MB_OK | MB_ICONERROR);
        DestroyWindow(g_hMainWnd); // WM_DESTROY will close event / delete CS, etc.
        return;
    }

    SetTimer(g_hMainWnd, HELPER_TIMER_ID, 250, NULL);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    UiHelperRemoveTrayIcon();
}

static BOOL UiHelperCreateMainWindow(void)
{
    const wchar_t* CLASS_NAME = L"VpnTrayWindowClass";

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = UiHelperWndProc;
    wc.hInstance = g_hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = CLASS_NAME;

    if (!RegisterClassExW(&wc))
    {
        if (GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
            return FALSE;
    }

    g_hMainWnd = CreateWindowExW(
        0,
        CLASS_NAME,
        g_appTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        300, 200,
        NULL,
        NULL,
        g_hInst,
        NULL);

    if (!g_hMainWnd)
    {
        return FALSE;
    }

    ShowWindow(g_hMainWnd, SW_HIDE);
    UpdateWindow(g_hMainWnd);

    return TRUE;
}

static BOOL UiHelperAddTrayIcon(void)
{
    NOTIFYICONDATAW nid;
    ZeroMemory(&nid, sizeof(nid));

    nid.cbSize = sizeof(nid);
    nid.hWnd = g_hMainWnd;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WMAPP_TRAYICON;
    nid.hIcon = (HICON)LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_HELPER),
        IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);

    lstrcpynW(nid.szTip, g_appTitle, ARRAYSIZE(nid.szTip));

    return Shell_NotifyIconW(NIM_ADD, &nid) ? TRUE : FALSE;
}

static void UiHelperRemoveTrayIcon(void)
{
    NOTIFYICONDATAW nid;
    ZeroMemory(&nid, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_hMainWnd;
    nid.uID = 1;

    Shell_NotifyIconW(NIM_DELETE, &nid);
}

static void UiHelperShowTrayMenu(HWND hWnd)
{
    POINT pt;
    GetCursorPos(&pt);

    HMENU hMenu = CreatePopupMenu();
    if (!hMenu)
        return;

    bool connected = false;
    if (!IsEmptyWStr(g_currentAccountName))
    {
        connected = (HelperGetAccountStatus(g_currentAccountName) == ACCOUNT_STATUS_CONNECTED);
    }

    wchar_t loggedUser[256];
    bool hasLogin = false;

    if (!connected)
    {
        loggedUser[0] = L'\0';
        hasLogin = HelperGetLoggedInOidcUser(loggedUser, _countof(loggedUser));
    }

    // Connect / Disconnect
    if (connected)
    {
        InsertMenuW(hMenu, -1,
            MF_BYPOSITION | MF_STRING,
            IDM_TRAY_DISCONNECT,
            L"Disconnect");
    }
    else
    {
        InsertMenuW(hMenu, -1,
            MF_BYPOSITION | MF_STRING,
            IDM_TRAY_CONNECT,
            L"Connect");
    }

    InsertMenuW(hMenu, -1,
        MF_BYPOSITION | MF_SEPARATOR,
        0,
        NULL);

    // Logout
    if (!connected && hasLogin)
    {
        HMENU hLogoutSub = CreatePopupMenu();

        wchar_t logoutRootText[256];
        if (loggedUser[0] != L'\0')
            _snwprintf_s(logoutRootText, _countof(logoutRootText), _TRUNCATE, L"Log out (%s)", loggedUser);
        else
            lstrcpynW(logoutRootText, L"Log out", _countof(logoutRootText));

        AppendMenuW(hLogoutSub, MF_STRING, IDM_TRAY_LOGOUT_TOKENS, L"Log out");
        AppendMenuW(hLogoutSub, MF_STRING, IDM_TRAY_LOGOUT_FORGET, L"Log out & clear browser data");

        InsertMenuW(hMenu, -1,
            MF_BYPOSITION | MF_POPUP,
            (UINT_PTR)hLogoutSub,
            logoutRootText);

        InsertMenuW(hMenu, -1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);
    }

    InsertMenuW(hMenu, -1, MF_BYPOSITION | MF_STRING, IDM_TRAY_ABOUT, L"About");
    InsertMenuW(hMenu, -1, MF_BYPOSITION | MF_SEPARATOR, 0, NULL);

    InsertMenuW(hMenu, -1,
        MF_BYPOSITION | MF_STRING,
        IDM_TRAY_EXIT,
        L"Exit");

    SetForegroundWindow(hWnd);
    TrackPopupMenu(hMenu,
        TPM_BOTTOMALIGN | TPM_RIGHTALIGN,
        pt.x, pt.y,
        0, hWnd, NULL);

    DestroyMenu(hMenu);
}

static void UiHelperUpdateTrayIcon(bool connected, const wchar_t* tooltip)
{
    NOTIFYICONDATAW nid;
    ZeroMemory(&nid, sizeof(nid));

    nid.cbSize = sizeof(nid);
    nid.hWnd = g_hMainWnd;
    nid.uID = 1;
    nid.uFlags = NIF_TIP | NIF_ICON;
    
    UINT iconId = CmGetTrayIconId(g_trayAnimation, g_trayCounter);

    HICON hIcon = LoadSmallIcon(iconId);
    nid.hIcon = hIcon;

    if (tooltip && tooltip[0] != L'\0')
        lstrcpynW(nid.szTip, tooltip, ARRAYSIZE(nid.szTip));
    else
        lstrcpynW(nid.szTip, g_appTitle, ARRAYSIZE(nid.szTip));

    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

static void HelperShowAbout(HWND hWnd)
{
    wchar_t appTitle[256], appVer[64], cr[256];

    if (!GetSelfVersionStringW(L"FileDescription", appTitle, _countof(appTitle)) ||
        !GetSelfVersionStringW(L"ProductVersion", appVer, _countof(appVer)) ||
        !GetSelfVersionStringW(L"LegalCopyright", cr, _countof(cr)))
    {
        MessageBoxW(hWnd, L"VERSIONINFO is missing in vpnuihelper.exe.", L"About", MB_OK | MB_ICONERROR);
        return;
    }

    wchar_t svcTitle[256] = L"SoftEther VPN Client service";
    wchar_t svcRaaVer[64] = L"N/A";
    wchar_t svcUpVer[64] = L"N/A";

    wchar_t tmp[256];

    if (GetServiceVersionStringW(L"FileDescription", tmp, _countof(tmp)))
        lstrcpynW(svcTitle, tmp, _countof(svcTitle));

    if (GetServiceVersionStringW(L"ProductVersion", tmp, _countof(tmp)))
        lstrcpynW(svcRaaVer, tmp, _countof(svcRaaVer));

    if (GetServiceVersionStringW(L"UpstreamVersion", tmp, _countof(tmp)))
        lstrcpynW(svcUpVer, tmp, _countof(svcUpVer));

    NormalizeVersionDotsInPlaceW(appVer, _countof(appVer));
    NormalizeVersionDotsInPlaceW(svcRaaVer, _countof(svcRaaVer));
    NormalizeVersionDotsInPlaceW(svcUpVer, _countof(svcUpVer));

    wchar_t msg[1200];
    _snwprintf_s(msg, _countof(msg), _TRUNCATE,
        L"%s\n"
        L"Version: %s\n"
        L"\n"
        L"%s\n"
        L"RAA Version: %s\n"
        L"Upstream: %s\n"
        L"\n"
        L"%s",
        appTitle, appVer,
        svcTitle, svcRaaVer, svcUpVer,
        cr);

    MessageBoxW(hWnd, msg, L"About", MB_OK | MB_ICONINFORMATION);
}

static LRESULT CALLBACK UiHelperWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WMAPP_TRAYICON:
    {
        if (LOWORD(lParam) == WM_RBUTTONUP || LOWORD(lParam) == WM_CONTEXTMENU)
        {
            UiHelperShowTrayMenu(hWnd);
        }
        break;
    }

    case WM_TIMER:
        if (wParam == HELPER_TIMER_ID)
        {
            bool connected = false;

            if (!IsEmptyWStr(g_currentAccountName))
            {
                ACCOUNT_STATUS st = HelperGetAccountStatus(g_currentAccountName);
                if (st == ACCOUNT_STATUS_CONNECTED)
                {
                    connected = true;
                }
                else if (st == ACCOUNT_STATUS_DISCONNECTED)
                {
                    connected = false;
                }
                else
                {
                    connected = g_lastConnected; // UNKNOWN
                }
            }
            else
            {
                connected = HelperIsAnyConnected();
            }

            // Edge: disconnected -> connected
            if (connected && !g_lastConnected)
            {
                char dev_name[128];
                Zero(dev_name, sizeof(dev_name));

                if (HelperGetConnectedDeviceName(dev_name, sizeof(dev_name)))
                {
                    HelperRequestPublicIpJobRestart(dev_name);
                }
                else
                {
                    HelperResetPublicIpCache();
                }

                EnterCriticalSection(&g_publicIpLock);
                g_publicIpNextRefreshTick = Tick64() + PUBLIC_IP_REFRESH_INTERVAL_MS;
                LeaveCriticalSection(&g_publicIpLock);
            }

            // Edge: connected -> disconnected
            if (!connected && g_lastConnected)
            {
                InterlockedIncrement(&g_publicIpGen);

                if (g_publicIpCancelEvent != NULL)
                {
                    SetEvent(g_publicIpCancelEvent);
                }

                EnterCriticalSection(&g_publicIpLock);
                if (g_publicIpPendingDevName)
                { 
                    Free(g_publicIpPendingDevName);
                    g_publicIpPendingDevName = NULL;
                }
                g_publicIpPendingGen = 0;
                LeaveCriticalSection(&g_publicIpLock);

                HelperResetPublicIpCache();
            }

            if (connected)
            {
                HelperMaybeSchedulePeriodicPublicIpRefresh();
                HelperTryStartPendingPublicIpJob();
            }

            wchar_t tip[256];

            EnterCriticalSection(&g_publicIpLock);
            if (connected)
            {
                g_trayAnimation = true;
                g_trayCounter++;

                if (g_publicIpValid && g_publicIp[0] != 0)
                {
                    wchar_t wip[64];
                    MultiByteToWideChar(CP_UTF8, 0, g_publicIp, -1, wip, _countof(wip));

                    _snwprintf_s(tip, _countof(tip), _TRUNCATE,
                        L"SoftEther VPN\nConnected\nPublic IP: %s", wip);
                }
                else if (g_publicIpInProgress)
                {
                    _snwprintf_s(tip, _countof(tip), _TRUNCATE,
                        L"SoftEther VPN\nConnected\nPublic IP: resolving...");
                }
                else
                {
                    _snwprintf_s(tip, _countof(tip), _TRUNCATE,
                        L"SoftEther VPN\nConnected");
                }
            }
            else
            {
                g_trayAnimation = false;
                g_trayCounter = 0;

                _snwprintf_s(tip, _countof(tip), _TRUNCATE,
                    L"SoftEther VPN\nNot connected");
            }
            LeaveCriticalSection(&g_publicIpLock);

            g_lastConnected = connected;
            UiHelperUpdateTrayIcon(connected, tip);
            return 0;
        }
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDM_TRAY_CONNECT:
            HelperConnectFirstAccount(hWnd);
            return 0;

        case IDM_TRAY_DISCONNECT:
            HelperDisconnectActiveAccounts(hWnd);
            return 0;

        case IDM_TRAY_LOGOUT_TOKENS:
            HelperLogoutAllOidcAccounts(hWnd);
            return 0;

        case IDM_TRAY_LOGOUT_FORGET:
            HelperLogoutAllOidcAccountsAndForget(hWnd);
            return 0;

        case IDM_TRAY_ABOUT:
            HelperShowAbout(hWnd);
            return 0;

        case IDM_TRAY_EXIT:
            PostMessageW(hWnd, WM_CLOSE, 0, 0);
            return 0;
        }
        break;

    case WM_MENUSELECT:
    {
        UINT item = LOWORD(wParam);
        UINT flags = HIWORD(wParam);

        if (flags == 0xFFFF && item == 0)
        {
            return 0;
        }

        if (flags & MF_POPUP)
        {
            UiHelperUpdateTrayIcon(g_lastConnected, L"Log out options");
            return 0;
        }

        switch (item)
        {
        case IDM_TRAY_LOGOUT_TOKENS:
            UiHelperUpdateTrayIcon(g_lastConnected, L"Log out: clear saved tokens");
            return 0;

        case IDM_TRAY_LOGOUT_FORGET:
            UiHelperUpdateTrayIcon(g_lastConnected, L"Log out and forget: clear tokens and browser data");
            return 0;
        }

        return 0;
    }

    case WM_CLOSE:
        DestroyWindow(hWnd);
        return 0;

    case WM_DESTROY:
        KillTimer(hWnd, HELPER_TIMER_ID);
        HelperDisconnectFromService();

        if (g_publicIpCancelEvent)
            SetEvent(g_publicIpCancelEvent);

        if (g_publicIpThread != NULL)
        {
            DWORD w = WaitForSingleObject(g_publicIpThread, 30000);

            if (w == WAIT_TIMEOUT)
            {
                // Safety: do not continue normal cleanup; worker may still touch Cedar/Mayaqua or g_publicIpLock
                ExitProcess(0);
            }

            CloseHandle(g_publicIpThread);
            g_publicIpThread = NULL;
        }

        if (g_publicIpPendingDevName)
        {
            Free(g_publicIpPendingDevName);
            g_publicIpPendingDevName = NULL;
        }

        if (g_publicIpCancelEvent)
        {
            CloseHandle(g_publicIpCancelEvent);
            g_publicIpCancelEvent = NULL;
        }

        DeleteCriticalSection(&g_publicIpLock);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static bool HelperConnectToService(void)
{
    if (g_rc != NULL)
        return true;

    bool bad_pass = false;
    bool no_remote = false;

    g_rc = CcConnectRpc("localhost", "", &bad_pass, &no_remote, 0);

    return g_rc != NULL;
}

static void HelperDisconnectFromService(void)
{
    if (g_rc != NULL) {
        CcDisconnectRpc(g_rc);
        g_rc = NULL;
    }
}

static bool HelperIsAnyConnected(void)
{
    if (!HelperConnectToService())
    {
        return false;
    }

    RPC_CLIENT_ENUM_ACCOUNT enum_account;
    Zero(&enum_account, sizeof(enum_account));

    if (CcEnumAccount(g_rc, &enum_account) != ERR_NO_ERROR || enum_account.NumItem == 0)
    {
        CiFreeClientEnumAccount(&enum_account);
        return false;
    }

    bool connected = false;

    for (UINT i = 0; i < enum_account.NumItem; ++i)
    {
        RPC_CLIENT_ENUM_ACCOUNT_ITEM* item = enum_account.Items[i];
        if (item == NULL)
            continue;

        RPC_CLIENT_GET_CONNECTION_STATUS st;
        Zero(&st, sizeof(st));

        lstrcpynW(st.AccountName,
            item->AccountName,
            _countof(st.AccountName));

        if (CcGetAccountStatus(g_rc, &st) == ERR_NO_ERROR &&
            st.Active && st.Connected)
        {
            connected = true;
            HelperSetCurrentAccount(item->AccountName);
            CiFreeClientGetConnectionStatus(&st);
            break;
        }

        // IMPORTANT: free X* that may be allocated inside st
        CiFreeClientGetConnectionStatus(&st);
    }

    CiFreeClientEnumAccount(&enum_account);
    return connected;
}

static bool HelperGetConnectedDeviceName(char* out_device_name, UINT out_device_name_size)
{
    if (out_device_name != NULL && out_device_name_size > 0)
    {
        out_device_name[0] = 0;
    }

    if (!HelperConnectToService())
    {
        return false;
    }

    RPC_CLIENT_ENUM_ACCOUNT enum_account;
    Zero(&enum_account, sizeof(enum_account));

    if (CcEnumAccount(g_rc, &enum_account) != ERR_NO_ERROR || enum_account.NumItem == 0)
    {
        CiFreeClientEnumAccount(&enum_account);
        return false;
    }

    bool found = false;

    for (UINT i = 0; i < enum_account.NumItem; ++i)
    {
        RPC_CLIENT_ENUM_ACCOUNT_ITEM* item = enum_account.Items[i];
        if (item == NULL)
        {
            continue;
        }

        RPC_CLIENT_GET_CONNECTION_STATUS st;
        Zero(&st, sizeof(st));

        lstrcpynW(st.AccountName,
            item->AccountName,
            _countof(st.AccountName));

        if (CcGetAccountStatus(g_rc, &st) == ERR_NO_ERROR &&
            st.Active && st.Connected)
        {
            if (out_device_name != NULL && out_device_name_size > 0)
            {
                StrCpy(out_device_name, out_device_name_size, item->DeviceName);
            }
            found = true;
            CiFreeClientGetConnectionStatus(&st);
            break;
        }

        CiFreeClientGetConnectionStatus(&st);
    }

    CiFreeClientEnumAccount(&enum_account);

    return found;
}

static ACCOUNT_STATUS HelperGetAccountStatus(const wchar_t* accountName)
{
    if (!HelperConnectToService())
    {
        return ACCOUNT_STATUS_UNKNOWN;
    }

    if (accountName == NULL || accountName[0] == 0)
    {
        return ACCOUNT_STATUS_UNKNOWN;
    }

    RPC_CLIENT_GET_CONNECTION_STATUS st;
    Zero(&st, sizeof(st));

    lstrcpynW(st.AccountName, accountName, _countof(st.AccountName));

    ACCOUNT_STATUS res = ACCOUNT_STATUS_UNKNOWN;

    UINT err = CcGetAccountStatus(g_rc, &st);
    if (err == ERR_NO_ERROR)
    {
        res = (st.Active && st.Connected) ? ACCOUNT_STATUS_CONNECTED : ACCOUNT_STATUS_DISCONNECTED;
    }

    // IMPORTANT: free X* that may be allocated inside st
    CiFreeClientGetConnectionStatus(&st);

    return res;
}

static void HelperConnectFirstAccount(HWND hWnd)
{
    if (!HelperConnectToService())
    {
        MessageBoxW(hWnd, L"VPN client service is not available.", L"Connect", MB_OK | MB_ICONERROR);
        return;
    }

    RPC_CLIENT_ENUM_ACCOUNT enum_account;
    ZeroMemory(&enum_account, sizeof(enum_account));

    if (CcEnumAccount(g_rc, &enum_account) != ERR_NO_ERROR || enum_account.NumItem == 0)
    {
        CiFreeClientEnumAccount(&enum_account);
        MessageBoxW(hWnd, L"No VPN accounts configured.", L"Connect", MB_OK | MB_ICONINFORMATION);
        return;
    }

    RPC_CLIENT_ENUM_ACCOUNT_ITEM* item = enum_account.Items[0];
    if (item == NULL)
    {
        CiFreeClientEnumAccount(&enum_account);
        MessageBoxW(hWnd, L"No VPN accounts available.", L"Connect", MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (enum_account.NumItem > 1)
    {
        MessageBoxW(hWnd,
            L"Multiple accounts detected. Helper will use the first one.",
            L"Connect",
            MB_OK | MB_ICONINFORMATION);
    }

    RPC_CLIENT_CONNECT client_connect;
    ZeroMemory(&client_connect, sizeof(client_connect));

    lstrcpynW(client_connect.AccountName,
        item->AccountName,
        _countof(client_connect.AccountName));

    UINT ret = CcConnect(g_rc, &client_connect);

    if (ret != ERR_NO_ERROR)
    {
        wchar_t msg[256];
        _snwprintf_s(msg, _countof(msg), _TRUNCATE,
            L"Failed to start connection.\nError code: %u", ret);
        MessageBoxW(hWnd, msg, L"Connect", MB_OK | MB_ICONERROR);
    }
    else
    {
        HelperSetCurrentAccount(client_connect.AccountName);
        // Without any progress window, timer will updating status and animation
    }

    CiFreeClientEnumAccount(&enum_account);
}

static void HelperDisconnectActiveAccounts(HWND hWnd)
{
    if (!HelperConnectToService())
    {
        MessageBoxW(hWnd, L"VPN client service is not available.", L"Disconnect", MB_OK | MB_ICONERROR);
        return;
    }

    RPC_CLIENT_ENUM_ACCOUNT enum_account;
    memset(&enum_account, 0, sizeof(enum_account));

    if (CcEnumAccount(g_rc, &enum_account) != ERR_NO_ERROR || enum_account.NumItem == 0)
    {
        MessageBoxW(hWnd, L"No VPN accounts configured.", L"Disconnect", MB_OK | MB_ICONINFORMATION);
        CiFreeClientEnumAccount(&enum_account);
        return;
    }

    bool anyDisconnected = false;

    for (UINT i = 0; i < enum_account.NumItem; ++i)
    {
        RPC_CLIENT_ENUM_ACCOUNT_ITEM* item = enum_account.Items[i];
        if (item == NULL)
            continue;

        RPC_CLIENT_GET_CONNECTION_STATUS connect_status;
        memset(&connect_status, 0, sizeof(connect_status));
        lstrcpynW(connect_status.AccountName,
            item->AccountName,
            _countof(connect_status.AccountName));

        if (CcGetAccountStatus(g_rc, &connect_status) == ERR_NO_ERROR &&
            connect_status.Active && connect_status.Connected)
        {
            RPC_CLIENT_CONNECT client_connect;
            memset(&client_connect, 0, sizeof(client_connect));
            lstrcpynW(client_connect.AccountName,
                item->AccountName,
                _countof(client_connect.AccountName));

            UINT ret = CcDisconnect(g_rc, &client_connect);
            if (ret == ERR_NO_ERROR)
            {
                anyDisconnected = true;
                HelperSetCurrentAccount(L"");
            }
        }

        // IMPORTANT: free X* that may be allocated inside st
        CiFreeClientGetConnectionStatus(&connect_status);
    }

    CiFreeClientEnumAccount(&enum_account);

    HelperResetPublicIpCache();

    if (!anyDisconnected)
    {
        MessageBoxW(hWnd, L"No active VPN connections to disconnect.", L"Disconnect", MB_OK | MB_ICONINFORMATION);
    }
}

static void HelperResetPublicIpCache()
{
    EnterCriticalSection(&g_publicIpLock);

    g_publicIp[0] = 0;
    g_publicIpValid = false;
    g_publicIpInProgress = false;

    g_publicIpNextRefreshTick = 0;

    LeaveCriticalSection(&g_publicIpLock);
}

// Performs a simple GET request to an external service that returns the IP as plain text.
// Returns true if out_ip is filled with a valid IPv4 string.
static bool HelperGetPublicIp(char* out_ip, UINT out_ip_size, HANDLE cancelEvent)
{
    if (!out_ip || out_ip_size == 0) return false;
    out_ip[0] = 0;

    if (HelperIsCancelSignaled(cancelEvent))
        return false;

    const wchar_t* host = L"ifconfig.co";
    const wchar_t* path = L"/ip";

    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    bool ok = false;

    char resp[256];
    Zero(resp, sizeof(resp));
    DWORD resp_len = 0;

    hSession = WinHttpOpen(L"SoftEtherVPN-UiHelper/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) goto cleanup;

    WinHttpSetTimeouts(hSession, 2000, 2000, 2000, 2000);

    hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) goto cleanup;

    hRequest = WinHttpOpenRequest(hConnect,
        L"GET",
        path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) goto cleanup;

    WinHttpAddRequestHeaders(hRequest,
        L"Accept: text/plain\r\n",
        (DWORD)-1,
        WINHTTP_ADDREQ_FLAG_ADD);

    if (HelperIsCancelSignaled(cancelEvent)) goto cleanup;

    if (!WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0,
        0, 0))
        goto cleanup;

    if (HelperIsCancelSignaled(cancelEvent)) goto cleanup;

    if (!WinHttpReceiveResponse(hRequest, NULL))
        goto cleanup;

    for (;;)
    {
        if (HelperIsCancelSignaled(cancelEvent)) goto cleanup;

        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail))
            goto cleanup;

        if (avail == 0)
            break;

        DWORD cap = (DWORD)(sizeof(resp) - 1 - resp_len);
        if (cap == 0) break;

        DWORD to_read = (avail < cap) ? avail : cap;
        DWORD read = 0;

        if (!WinHttpReadData(hRequest, resp + resp_len, to_read, &read))
            goto cleanup;

        if (read == 0)
            break;

        resp_len += read;
    }

    resp[resp_len] = 0;
    Trim(resp);

    IP ip;
    Zero(&ip, sizeof(ip));
    if (StrToIP(&ip, resp) && IsIP4(&ip))
    {
        StrCpy(out_ip, out_ip_size, resp);
        ok = true;
    }

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return ok;
}

static bool HelperIsGoodIPv4(const SOCKADDR* sa)
{
    const SOCKADDR_IN* sin;
    UINT ip;

    if (sa == NULL)
    {
        return false;
    }

    if (sa->sa_family != AF_INET)
    {
        return false;
    }

    sin = (const SOCKADDR_IN*)sa;
    ip = ntohl(sin->sin_addr.s_addr);

    if (ip == 0)
    {
        return false;
    }

    // Ignore link-local 169.254.0.0/16
    if ((ip & 0xFFFF0000u) == 0xA9FE0000u)
    {
        return false;
    }

    return true;
}

static bool HelperIsCancelSignaled(HANDLE cancelEvent)
{
    if (cancelEvent == NULL)
        return false;

    DWORD w = WaitForSingleObject(cancelEvent, 0);
    return (w == WAIT_OBJECT_0 || w == WAIT_FAILED);
}

// Waits until the SoftEther VPN adapter with the given DeviceName gets an IPv4 address.
// The Description of such adapters looks like: "VPN Client Adapter - <DeviceName>".
// Returns true if a valid IPv4 address appears before the timeout.
static bool HelperWaitForVpnAdapterIpByDeviceName(const char* device_name, UINT timeout_ms, HANDLE cancelEvent)
{
    const UINT step_ms = 500;
    UINT elapsed = 0;

    if (device_name == NULL || device_name[0] == 0)
    {
        return false;
    }

    // DeviceName -> wide
    wchar_t dev_name_w[128];
    Zero(dev_name_w, sizeof(dev_name_w));
    MultiByteToWideChar(
        CP_ACP,
        0,
        device_name,
        -1,
        dev_name_w,
        _countof(dev_name_w));

    while (elapsed < timeout_ms)
    {
        if (HelperIsCancelSignaled(cancelEvent))
            return false;

        ULONG buf_len = 0;
        DWORD ret = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST |
            GAA_FLAG_SKIP_MULTICAST |
            GAA_FLAG_SKIP_DNS_SERVER,
            NULL,
            NULL,
            &buf_len);

        if (ret == ERROR_BUFFER_OVERFLOW && buf_len != 0)
        {
            IP_ADAPTER_ADDRESSES* addrs = (IP_ADAPTER_ADDRESSES*)ZeroMalloc(buf_len);
            if (addrs == NULL)
            {
                return false;
            }

            ret = GetAdaptersAddresses(
                AF_UNSPEC,
                GAA_FLAG_SKIP_ANYCAST |
                GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_SKIP_DNS_SERVER,
                NULL,
                addrs,
                &buf_len);

            if (ret == NO_ERROR)
            {
                IP_ADAPTER_ADDRESSES* aa;
                for (aa = addrs; aa != NULL; aa = aa->Next)
                {
                    const wchar_t* desc = (aa->Description != NULL) ? aa->Description : L"";
                    bool match = false;

                    if (wcsstr(desc, L"VPN Client Adapter - ") == desc)
                    {
                        if (wcsstr(desc, dev_name_w) != NULL)
                        {
                            match = true;
                        }
                    }

                    if (!match)
                    {
                        continue;
                    }

                    IP_ADAPTER_UNICAST_ADDRESS* u;
                    for (u = aa->FirstUnicastAddress; u != NULL; u = u->Next)
                    {
                        if (HelperIsGoodIPv4(u->Address.lpSockaddr))
                        {
                            Free(addrs);
                            return true;
                        }
                    }
                }
            }

            Free(addrs);
        }

        DWORD w = WaitForSingleObject(cancelEvent, step_ms);
        if (w == WAIT_OBJECT_0 || w == WAIT_FAILED)
        {
            return false; // cancel or error
        }
        elapsed += step_ms;
    }

    return false;
}

static void HelperRequestPublicIpJobRestart(const char* device_name)
{
    if (device_name == NULL || device_name[0] == 0)
        return;

    char* copy = ZeroMalloc(StrLen(device_name) + 1);
    if (copy == NULL)
        return;

    StrCpy(copy, StrLen(device_name) + 1, device_name);

    bool need_cancel = false;

    EnterCriticalSection(&g_publicIpLock);

    LONG newGen = InterlockedIncrement(&g_publicIpGen);
    g_publicIpPendingGen = newGen;

    if (g_publicIpPendingDevName != NULL)
        Free(g_publicIpPendingDevName);

    g_publicIpPendingDevName = copy;

    if (g_publicIpThread != NULL && WaitForSingleObject(g_publicIpThread, 0) == WAIT_TIMEOUT)
    {
        g_publicIpInProgress = true;
        g_publicIpValid = false;
        g_publicIp[0] = 0;

        need_cancel = true;
    }

    LeaveCriticalSection(&g_publicIpLock);

    if (need_cancel && g_publicIpCancelEvent != NULL)
        SetEvent(g_publicIpCancelEvent);
}

static void HelperTryStartPendingPublicIpJob(void)
{
    // If we have a thread handle, only one worker at a time.
    if (g_publicIpThread != NULL)
    {
        DWORD wr = WaitForSingleObject(g_publicIpThread, 0);
        if (wr == WAIT_TIMEOUT)
            return;

        CloseHandle(g_publicIpThread);
        g_publicIpThread = NULL;
    }

    char* dev = NULL;
    LONG gen = 0;

    EnterCriticalSection(&g_publicIpLock);

    dev = g_publicIpPendingDevName;
    gen = g_publicIpPendingGen;

    if (dev == NULL)
    {
        LeaveCriticalSection(&g_publicIpLock);
        return;
    }

    // TRANSFER OWNERSHIP to the worker
    g_publicIpPendingDevName = NULL;
    g_publicIpPendingGen = 0;

    ResetEvent(g_publicIpCancelEvent);

    g_publicIp[0] = 0;
    g_publicIpValid = false;
    g_publicIpInProgress = true;

    LeaveCriticalSection(&g_publicIpLock);

    PUBLIC_IP_JOB* job = (PUBLIC_IP_JOB*)ZeroMalloc(sizeof(PUBLIC_IP_JOB));
    if (job == NULL)
    {
        Free(dev);
        EnterCriticalSection(&g_publicIpLock);
        g_publicIpInProgress = false;
        LeaveCriticalSection(&g_publicIpLock);
        return;
    }

    job->dev_name = dev;
    job->cancel_event = g_publicIpCancelEvent;
    job->gen = gen;

    HANDLE hThread = CreateThread(NULL, 0, HelperPublicIpThreadProc, job, 0, NULL);
    if (hThread == NULL)
    {
        Free(dev);
        Free(job);
        EnterCriticalSection(&g_publicIpLock);
        g_publicIpInProgress = false;
        LeaveCriticalSection(&g_publicIpLock);
        return;
    }

    g_publicIpThread = hThread;
}

static DWORD WINAPI HelperPublicIpThreadProc(LPVOID param)
{
    PUBLIC_IP_JOB* job = (PUBLIC_IP_JOB*)param;

    bool ready = true;
    bool ok = false;
    bool cancelled = false;
    char ip[64] = { 0 };

    if (job == NULL)
    {
        return 0;
    }

    for (;;)
    {
        DWORD w = WaitForSingleObject(job->cancel_event, 0);
        if (w == WAIT_OBJECT_0 || w == WAIT_FAILED)
        {
            cancelled = true;
            break;
        }

        // Wait until adapter gets IPv4 (cancel-aware)
        if (job->dev_name != NULL && job->dev_name[0] != 0)
        {
            ready = HelperWaitForVpnAdapterIpByDeviceName(job->dev_name, 10000, job->cancel_event);
            if (!ready)
                break;
        }

        w = WaitForSingleObject(job->cancel_event, 0);
        if (w == WAIT_OBJECT_0 || w == WAIT_FAILED)
        {
            cancelled = true;
            break;
        }

        ok = HelperGetPublicIp(ip, sizeof(ip), job->cancel_event);
        break;
    }

    // Publish result only if this job is still the latest.
    LONG curGen = InterlockedCompareExchange(&g_publicIpGen, 0, 0);
    if (job->gen == curGen)
    {
        EnterCriticalSection(&g_publicIpLock);

        if (!cancelled && ready && ok && ip[0] != 0)
        {
            StrCpy(g_publicIp, sizeof(g_publicIp), ip);
            g_publicIpValid = true;
        }
        else
        {
            g_publicIp[0] = 0;
            g_publicIpValid = false;
        }

        g_publicIpInProgress = false;
        LeaveCriticalSection(&g_publicIpLock);
    }

    if (job->dev_name != NULL)
        Free(job->dev_name);

    Free(job);
    return 0;
}

static void HelperMaybeSchedulePeriodicPublicIpRefresh(void)
{
    UINT64 now = Tick64();

    bool inProgress, hasPending;
    UINT64 nextTick;

    EnterCriticalSection(&g_publicIpLock);
    inProgress = g_publicIpInProgress;
    hasPending = (g_publicIpPendingDevName != NULL);
    nextTick = g_publicIpNextRefreshTick;
    LeaveCriticalSection(&g_publicIpLock);

    if (inProgress || hasPending || now < nextTick)
        return;

    char dev_name[128];
    Zero(dev_name, sizeof(dev_name));

    if (!HelperGetConnectedDeviceName(dev_name, sizeof(dev_name)))
    {
        EnterCriticalSection(&g_publicIpLock);
        g_publicIpNextRefreshTick = now + PUBLIC_IP_REFRESH_INTERVAL_MS;
        LeaveCriticalSection(&g_publicIpLock);
        return;
    }

    HelperRequestPublicIpJobRestart(dev_name);

    EnterCriticalSection(&g_publicIpLock);
    g_publicIpNextRefreshTick = now + PUBLIC_IP_REFRESH_INTERVAL_MS;
    LeaveCriticalSection(&g_publicIpLock);
}

static bool HelperGetLoggedInOidcUser(wchar_t* out_user, UINT out_user_size)
{
    if (out_user && out_user_size)
    {
        out_user[0] = L'\0';
    }

    if (!HelperConnectToService())
    {
        return false;
    }

    RPC_OIDC_GET_LOGGED_IN_USER r;
    Zero(&r, sizeof(r));

    UINT err = CcOidcGetLoggedInUser(g_rc, &r);
    if (err != ERR_NO_ERROR)
    {
        return false;
    }

    if (!r.HasLogin)
    {
        return false;
    }

    if (out_user && out_user_size)
    {
        MultiByteToWideChar(
            CP_UTF8,
            0,
            r.Username,
            -1,
            out_user,
            out_user_size
        );
    }

    return true;
}

static void HelperLogoutAllOidcAccounts(HWND hWnd)
{
    if (!HelperConnectToService())
    {
        MessageBoxW(hWnd,
            L"VPN client service is not available.",
            L"Log out",
            MB_OK | MB_ICONERROR);
        return;
    }

    if (!IsEmptyWStr(g_currentAccountName))
    {
        bool isCurrentAccountConnected = (HelperGetAccountStatus(g_currentAccountName) == ACCOUNT_STATUS_CONNECTED);
        if (isCurrentAccountConnected)
        {
            MessageBoxW(
                hWnd,
                L"VPN connection is active.\nPlease disconnect before logging out.",
                L"Log out",
                MB_OK | MB_ICONWARNING);
            return;
        }

    }

    RPC_OIDC_LOGOUT_ALL_RESULT rpc_logout;
    Zero(&rpc_logout, sizeof(rpc_logout));

    UINT err = CcOidcLogoutAllAccounts(g_rc, &rpc_logout);
    if (err != ERR_NO_ERROR)
    {
        wchar_t msg[256];
        _snwprintf_s(msg, _countof(msg), _TRUNCATE,
            L"Failed to log out OIDC accounts.\nError code: %u", err);
        MessageBoxW(hWnd, msg, L"Log out", MB_OK | MB_ICONERROR);
        return;
    }

    if (!rpc_logout.AnyUpdatedAccounts)
    {
        MessageBoxW(
            hWnd,
            L"No OIDC account to log out.",
            L"Log out",
            MB_OK | MB_ICONINFORMATION);
    }
    else if (!rpc_logout.AnyErrorsDuringLogout)
    {
        MessageBoxW(
            hWnd,
            L"Logged out successfully.",
            L"Log out",
            MB_OK | MB_ICONINFORMATION);
    }
    else
    {
        MessageBoxW(
            hWnd,
            L"Logout completed with some errors.\nDetails will be written to the log.",
            L"Log out",
            MB_OK | MB_ICONWARNING);
    }
}

static void HelperLogoutAllOidcAccountsAndForget(HWND hWnd)
{
    if (!HelperConnectToService())
    {
        MessageBoxW(hWnd, L"VPN client service is not available.", L"Log out", MB_OK | MB_ICONERROR);
        return;
    }

    if (!IsEmptyWStr(g_currentAccountName))
    {
        bool isCurrentAccountConnected = (HelperGetAccountStatus(g_currentAccountName) == ACCOUNT_STATUS_CONNECTED);
        if (isCurrentAccountConnected)
        {
            MessageBoxW(hWnd, L"VPN connection is active.\nPlease disconnect before logging out.", L"Log out", MB_OK | MB_ICONWARNING);
            return;
        }
        
    }

    RPC_OIDC_LOGOUT_ALL_RESULT r;
    Zero(&r, sizeof(r));

    UINT err = CcOidcLogoutAllAccountsEx(g_rc, true /*forget*/, &r);

    if (err != ERR_NO_ERROR)
    {
        wchar_t msg[256];
        _snwprintf_s(msg, _countof(msg), _TRUNCATE,
            L"Failed to log out.\nError code: %u", err);
        MessageBoxW(hWnd, msg, L"Log out", MB_OK | MB_ICONERROR);
        return;
    }

    if (!r.AnyUpdatedAccounts)
    {
        MessageBoxW(hWnd, L"No OIDC account to log out.", L"Log out", MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (!r.AnyErrorsDuringLogout && r.AnyBrowserDataPurged && !r.AnyErrorsDuringPurge)
    {
        MessageBoxW(hWnd, L"Logged out and cleared browser data.", L"Log out", MB_OK | MB_ICONINFORMATION);
    }
    else if (!r.AnyErrorsDuringLogout && (!r.AnyBrowserDataPurged || r.AnyErrorsDuringPurge))
    {
        MessageBoxW(hWnd,
            L"Logged out successfully, but browser sign-in data could not be fully cleared.\nSee log for details.",
            L"Log out",
            MB_OK | MB_ICONWARNING);
    }
    else
    {
        MessageBoxW(hWnd,
            L"Logout completed with some errors.\nSee log for details.",
            L"Log out",
            MB_OK | MB_ICONWARNING);
    }
}


// Attempting thread for starting the UI Helper
void UiHelperTryToExecUiHelperThread(THREAD* thread, void* param)
{
    bool first_flag = true;

    while (TryExecUiHelperHalt == false)
    {
        if (first_flag == false)
        {
            // Wait a little for other than the first time
            Wait(TryExecUiHelperHaltEvent, CM_TRY_EXEC_UI_HELPER_INTERVAL * 2);

            if (TryExecUiHelperHalt)
            {
                break;
            }
        }
        first_flag = false;

        if (TryExecUiHelperHalt == false)
        {
            if (TryExecUiHelperProcessHandle == NULL)
            {
                UiHelperTryToExecUiHelper();
            }
        }

        if (TryExecUiHelperHalt)
        {
            break;
        }

        if (TryExecUiHelperProcessHandle == NULL)
        {
            Wait(TryExecUiHelperHaltEvent, CM_TRY_EXEC_UI_HELPER_INTERVAL);
        }
        else
        {
            HANDLE handles[2];
            handles[0] = TryExecUiHelperProcessHandle;
            handles[1] = (HANDLE)TryExecUiHelperHaltEvent->pData;
            WaitForMultipleObjects(2, handles, false, CM_TRY_EXEC_UI_HELPER_INTERVAL);

            if (WaitForSingleObject(TryExecUiHelperProcessHandle, 0) != WAIT_TIMEOUT)
            {
                CloseHandle(TryExecUiHelperProcessHandle);
                TryExecUiHelperProcessHandle = NULL;
                if (TryExecUiHelperHalt)
                {
                    break;
                }
                Wait(TryExecUiHelperHaltEvent, CM_TRY_EXEC_UI_HELPER_INTERVAL * 2);
            }
        }
    }
}

// Initialize the UI Helper starting
void UiHelperInitTryToExecUiHelper()
{
    TryExecUiHelperProcessHandle = NULL;
    TryExecUiHelperHalt = false;
    TryExecUiHelperHaltEvent = NewEvent();
    TryExecUiHelperThread = NewThread(UiHelperTryToExecUiHelperThread, NULL);
}

// Stop the UI Helper
void UiHelperFreeTryToExecUiHelper()
{
    TryExecUiHelperHalt = true;
    Set(TryExecUiHelperHaltEvent);

    WaitThread(TryExecUiHelperThread, INFINITE);

    ReleaseThread(TryExecUiHelperThread);
    TryExecUiHelperThread = NULL;

    ReleaseEvent(TryExecUiHelperHaltEvent);
    TryExecUiHelperHaltEvent = NULL;

    TryExecUiHelperHalt = false;
    TryExecUiHelperProcessHandle = NULL;
}

// Attempt to start the UI Helper
void UiHelperTryToExecUiHelper()
{
    HANDLE h;
    // Check that it isn't already running
    if (CnCheckAlreadyExists(false))
    {
        // It have already started
        return;
    }

    h = (HANDLE)UiHelperExecUiHelperMain();

    if (h != NULL)
    {
        TryExecUiHelperProcessHandle = h;
    }
}

// Start the UI Helper
void* UiHelperExecUiHelperMain()
{
    HANDLE h;
    wchar_t tmp[MAX_SIZE];

    UniFormat(tmp, sizeof(tmp), L"%s\\%S", MsGetExeDirNameW(), CLIENT_WIN32_EXE_FILENAME);

    // Start
    h = Win32RunExW(tmp, SVC_ARG_UIHELP_W, false);

    return (void*)h;
}

static BOOL GetFileVersionStringW(const wchar_t* path, const wchar_t* key, wchar_t* out, DWORD out_cch)
{
    if (!path || !key || !out || out_cch == 0) return FALSE;
    out[0] = 0;

    DWORD handle = 0;
    DWORD sz = GetFileVersionInfoSizeW(path, &handle);
    if (!sz) return FALSE;

    BYTE* data = (BYTE*)LocalAlloc(LMEM_FIXED, sz);
    if (!data) return FALSE;

    BOOL ok = FALSE;

    if (GetFileVersionInfoW(path, 0, sz, data))
    {
        struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; } *t = NULL;
        UINT tlen = 0;

        if (VerQueryValueW(data, L"\\VarFileInfo\\Translation", (LPVOID*)&t, &tlen) &&
            t && tlen >= sizeof(*t))
        {
            wchar_t sub[256];
            _snwprintf_s(sub, _countof(sub), _TRUNCATE,
                L"\\StringFileInfo\\%04x%04x\\%s", t[0].wLanguage, t[0].wCodePage, key);

            void* val = NULL;
            UINT vlen = 0;

            if (VerQueryValueW(data, sub, &val, &vlen) && val && vlen > 0)
            {
                wcsncpy_s(out, out_cch, (const wchar_t*)val, _TRUNCATE);
                ok = TRUE;
            }
        }
    }

    LocalFree(data);
    return ok;
}

static BOOL GetSelfVersionStringW(const wchar_t* key, wchar_t* out, DWORD out_cch)
{
    wchar_t selfPath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, selfPath, _countof(selfPath)))
        return FALSE;

    return GetFileVersionStringW(selfPath, key, out, out_cch);
}

static BOOL ExtractExePathFromServiceCmdLine(const wchar_t* in, wchar_t* out, DWORD out_cch)
{
    if (!in || !out || out_cch == 0) return FALSE;
    out[0] = 0;

    while (*in == L' ' || *in == L'\t') in++;

    if (*in == L'"')
    {
        in++;
        const wchar_t* end = wcschr(in, L'"');
        if (!end) return FALSE;
        size_t len = (size_t)(end - in);
        if (len + 1 > out_cch) return FALSE;
        wmemcpy(out, in, len);
        out[len] = 0;
        return TRUE;
    }
    else
    {
        const wchar_t* end = in;
        while (*end && *end != L' ' && *end != L'\t') end++;
        size_t len = (size_t)(end - in);
        if (len + 1 > out_cch) return FALSE;
        wmemcpy(out, in, len);
        out[len] = 0;
        return TRUE;
    }
}

static BOOL GetServiceBinaryPathW(const wchar_t* serviceName, wchar_t* outPath, DWORD out_cch)
{
    BOOL ok = FALSE;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return FALSE;

    SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_CONFIG);
    if (!svc)
    {
        CloseServiceHandle(scm);
        return FALSE;
    }

    DWORD bytesNeeded = 0;
    QueryServiceConfigW(svc, NULL, 0, &bytesNeeded);

    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && bytesNeeded > 0)
    {
        BYTE* buf = (BYTE*)LocalAlloc(LMEM_FIXED, bytesNeeded);
        if (buf)
        {
            QUERY_SERVICE_CONFIGW* cfg = (QUERY_SERVICE_CONFIGW*)buf;
            if (QueryServiceConfigW(svc, cfg, bytesNeeded, &bytesNeeded))
            {
                ok = ExtractExePathFromServiceCmdLine(cfg->lpBinaryPathName, outPath, out_cch);
            }
            LocalFree(buf);
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

static BOOL GetServiceVersionStringW(const wchar_t* key, wchar_t* out, DWORD out_cch)
{
    if (!out || out_cch == 0) return FALSE;
    out[0] = 0;

    wchar_t svcExe[MAX_PATH];
    if (!GetServiceBinaryPathW(L"SEVPNCLIENTDEV", svcExe, _countof(svcExe)))
        return FALSE;

    return GetFileVersionStringW(svcExe, key, out, out_cch);
}

static void NormalizeVersionDotsInPlaceW(wchar_t* s, size_t cch)
{
    if (!s || cch == 0) return;

    // Extract up to 4 numbers from any string like "5, 2, 0, 5187" or "5.2.0.5187"
    unsigned nums[4] = { 0 };
    int n = 0;

    const wchar_t* p = s;
    while (*p && n < 4)
    {
        while (*p && (*p < L'0' || *p > L'9')) p++;
        if (!*p) break;

        nums[n++] = (unsigned)wcstoul(p, (wchar_t**)&p, 10);
    }

    if (n == 4)
    {
        _snwprintf_s(s, cch, _TRUNCATE, L"%u.%u.%u.%u", nums[0], nums[1], nums[2], nums[3]);
    }
    else if (n == 3)
    {
        _snwprintf_s(s, cch, _TRUNCATE, L"%u.%u.%u", nums[0], nums[1], nums[2]);
    }
    // else: leave as-is
}
