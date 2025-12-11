/**
 * version.dll Proxy
 * 
 * This is a proxy DLL that pretends to be Windows' version.dll
 * When the game loads, it loads our fake version.dll which:
 *   1. Loads the real version.dll from System32
 *   2. Forwards all version.dll calls to the real one
 *   3. Loads and initializes coa_extender.dll
 * 
 * USER INSTALLATION:
 *   1. Copy version.dll to game folder
 *   2. Copy coa_extender.dll to game folder  
 *   3. Create 'mods' folder, put mod DLLs there
 *   4. Play game normally through Steam
 * 
 * Build: This file is compiled separately as version.dll
 */

// Prevent windows.h from including winver.h
#define _WINVER_

#include <windows.h>
#include <stdio.h>

// Handle to the real version.dll
static HMODULE g_RealVersionDll = nullptr;

// Handle to our extender
static HMODULE g_ExtenderDll = nullptr;

// Original function pointers from real version.dll
static FARPROC p_GetFileVersionInfoA = nullptr;
static FARPROC p_GetFileVersionInfoByHandle = nullptr;
static FARPROC p_GetFileVersionInfoExA = nullptr;
static FARPROC p_GetFileVersionInfoExW = nullptr;
static FARPROC p_GetFileVersionInfoSizeA = nullptr;
static FARPROC p_GetFileVersionInfoSizeExA = nullptr;
static FARPROC p_GetFileVersionInfoSizeExW = nullptr;
static FARPROC p_GetFileVersionInfoSizeW = nullptr;
static FARPROC p_GetFileVersionInfoW = nullptr;
static FARPROC p_VerFindFileA = nullptr;
static FARPROC p_VerFindFileW = nullptr;
static FARPROC p_VerInstallFileA = nullptr;
static FARPROC p_VerInstallFileW = nullptr;
static FARPROC p_VerLanguageNameA = nullptr;
static FARPROC p_VerLanguageNameW = nullptr;
static FARPROC p_VerQueryValueA = nullptr;
static FARPROC p_VerQueryValueW = nullptr;

// Log file
static FILE* g_ProxyLog = nullptr;

static void ProxyLog(const char* format, ...) {
    if (!g_ProxyLog) {
        char path[MAX_PATH];
        GetModuleFileNameA(nullptr, path, MAX_PATH);
        char* slash = strrchr(path, '\\');
        if (slash) strcpy(slash + 1, "version_proxy.log");
        g_ProxyLog = fopen(path, "w");
    }
    if (!g_ProxyLog) return;
    
    va_list args;
    va_start(args, format);
    vfprintf(g_ProxyLog, format, args);
    fprintf(g_ProxyLog, "\n");
    fflush(g_ProxyLog);
    va_end(args);
}

static bool LoadRealVersionDll() {
    char systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    strcat(systemPath, "\\version.dll");
    
    g_RealVersionDll = LoadLibraryA(systemPath);
    if (!g_RealVersionDll) {
        ProxyLog("ERROR: Failed to load real version.dll from %s", systemPath);
        return false;
    }
    
    ProxyLog("Loaded real version.dll from %s", systemPath);
    
    // Get all function pointers
    p_GetFileVersionInfoA = GetProcAddress(g_RealVersionDll, "GetFileVersionInfoA");
    p_GetFileVersionInfoByHandle = GetProcAddress(g_RealVersionDll, "GetFileVersionInfoByHandle");
    p_GetFileVersionInfoExA = GetProcAddress(g_RealVersionDll, "GetFileVersionInfoExA");
    p_GetFileVersionInfoExW = GetProcAddress(g_RealVersionDll, "GetFileVersionInfoExW");
    p_GetFileVersionInfoSizeA = GetProcAddress(g_RealVersionDll, "GetFileVersionInfoSizeA");
    p_GetFileVersionInfoSizeExA = GetProcAddress(g_RealVersionDll, "GetFileVersionInfoSizeExA");
    p_GetFileVersionInfoSizeExW = GetProcAddress(g_RealVersionDll, "GetFileVersionInfoSizeExW");
    p_GetFileVersionInfoSizeW = GetProcAddress(g_RealVersionDll, "GetFileVersionInfoSizeW");
    p_GetFileVersionInfoW = GetProcAddress(g_RealVersionDll, "GetFileVersionInfoW");
    p_VerFindFileA = GetProcAddress(g_RealVersionDll, "VerFindFileA");
    p_VerFindFileW = GetProcAddress(g_RealVersionDll, "VerFindFileW");
    p_VerInstallFileA = GetProcAddress(g_RealVersionDll, "VerInstallFileA");
    p_VerInstallFileW = GetProcAddress(g_RealVersionDll, "VerInstallFileW");
    p_VerLanguageNameA = GetProcAddress(g_RealVersionDll, "VerLanguageNameA");
    p_VerLanguageNameW = GetProcAddress(g_RealVersionDll, "VerLanguageNameW");
    p_VerQueryValueA = GetProcAddress(g_RealVersionDll, "VerQueryValueA");
    p_VerQueryValueW = GetProcAddress(g_RealVersionDll, "VerQueryValueW");
    
    return true;
}

static void LoadExtender() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash) strcpy(slash + 1, "coa_extender.dll");
    
    ProxyLog("Loading extender from %s", path);
    
    g_ExtenderDll = LoadLibraryA(path);
    if (!g_ExtenderDll) {
        ProxyLog("WARNING: Failed to load coa_extender.dll (error %d)", GetLastError());
        ProxyLog("The game will run without the script extender.");
        return;
    }
    
    ProxyLog("Successfully loaded coa_extender.dll");
    
    // Call the extender's init function if it exports one
    typedef bool (*InitFunc)();
    InitFunc init = (InitFunc)GetProcAddress(g_ExtenderDll, "ExtenderInit");
    if (init) {
        if (init()) {
            ProxyLog("Extender initialized successfully");
        } else {
            ProxyLog("WARNING: Extender initialization returned false");
        }
    }
}

// DLL Entry Point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            
            ProxyLog("=== COA Script Extender Proxy ===");
            ProxyLog("version.dll proxy loaded");
            
            if (!LoadRealVersionDll()) {
                return FALSE;
            }
            
            // Load extender on a separate thread to avoid loader lock issues
            CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
                Sleep(100);  // Small delay to let the game initialize
                LoadExtender();
                return 0;
            }, nullptr, 0, nullptr);
            break;
            
        case DLL_PROCESS_DETACH:
            ProxyLog("Proxy unloading");
            if (g_ExtenderDll) {
                FreeLibrary(g_ExtenderDll);
            }
            if (g_RealVersionDll) {
                FreeLibrary(g_RealVersionDll);
            }
            if (g_ProxyLog) {
                fclose(g_ProxyLog);
            }
            break;
    }
    return TRUE;
}

// Export forwards - these forward calls to the real version.dll
// Using __declspec(naked) and inline asm for x86, or direct call for x64

#ifdef _WIN64
// 64-bit: Use direct function calls with NULL checks

extern "C" __declspec(dllexport) BOOL WINAPI GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    typedef BOOL(WINAPI* Func)(LPCSTR, DWORD, DWORD, LPVOID);
    if (!p_GetFileVersionInfoA) return FALSE;
    return ((Func)p_GetFileVersionInfoA)(lptstrFilename, dwHandle, dwLen, lpData);
}

extern "C" __declspec(dllexport) BOOL WINAPI GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    typedef BOOL(WINAPI* Func)(LPCWSTR, DWORD, DWORD, LPVOID);
    if (!p_GetFileVersionInfoW) return FALSE;
    return ((Func)p_GetFileVersionInfoW)(lptstrFilename, dwHandle, dwLen, lpData);
}

extern "C" __declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD(WINAPI* Func)(LPCSTR, LPDWORD);
    if (!p_GetFileVersionInfoSizeA) return 0;
    return ((Func)p_GetFileVersionInfoSizeA)(lptstrFilename, lpdwHandle);
}

extern "C" __declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD(WINAPI* Func)(LPCWSTR, LPDWORD);
    if (!p_GetFileVersionInfoSizeW) return 0;
    return ((Func)p_GetFileVersionInfoSizeW)(lptstrFilename, lpdwHandle);
}

extern "C" __declspec(dllexport) BOOL WINAPI GetFileVersionInfoExA(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    typedef BOOL(WINAPI* Func)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
    if (!p_GetFileVersionInfoExA) return FALSE;
    return ((Func)p_GetFileVersionInfoExA)(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);
}

extern "C" __declspec(dllexport) BOOL WINAPI GetFileVersionInfoExW(DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    typedef BOOL(WINAPI* Func)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
    if (!p_GetFileVersionInfoExW) return FALSE;
    return ((Func)p_GetFileVersionInfoExW)(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);
}

extern "C" __declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeExA(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD(WINAPI* Func)(DWORD, LPCSTR, LPDWORD);
    if (!p_GetFileVersionInfoSizeExA) return 0;
    return ((Func)p_GetFileVersionInfoSizeExA)(dwFlags, lpwstrFilename, lpdwHandle);
}

extern "C" __declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeExW(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD(WINAPI* Func)(DWORD, LPCWSTR, LPDWORD);
    if (!p_GetFileVersionInfoSizeExW) return 0;
    return ((Func)p_GetFileVersionInfoSizeExW)(dwFlags, lpwstrFilename, lpdwHandle);
}

extern "C" __declspec(dllexport) BOOL WINAPI VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen) {
    typedef BOOL(WINAPI* Func)(LPCVOID, LPCSTR, LPVOID*, PUINT);
    if (!p_VerQueryValueA) return FALSE;
    return ((Func)p_VerQueryValueA)(pBlock, lpSubBlock, lplpBuffer, puLen);
}

extern "C" __declspec(dllexport) BOOL WINAPI VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen) {
    typedef BOOL(WINAPI* Func)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
    if (!p_VerQueryValueW) return FALSE;
    return ((Func)p_VerQueryValueW)(pBlock, lpSubBlock, lplpBuffer, puLen);
}

extern "C" __declspec(dllexport) DWORD WINAPI VerFindFileA(DWORD uFlags, LPSTR szFileName, LPSTR szWinDir, LPSTR szAppDir, LPSTR szCurDir, PUINT puCurDirLen, LPSTR szDestDir, PUINT puDestDirLen) {
    typedef DWORD(WINAPI* Func)(DWORD, LPSTR, LPSTR, LPSTR, LPSTR, PUINT, LPSTR, PUINT);
    return ((Func)p_VerFindFileA)(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen);
}

extern "C" __declspec(dllexport) DWORD WINAPI VerFindFileW(DWORD uFlags, LPWSTR szFileName, LPWSTR szWinDir, LPWSTR szAppDir, LPWSTR szCurDir, PUINT puCurDirLen, LPWSTR szDestDir, PUINT puDestDirLen) {
    typedef DWORD(WINAPI* Func)(DWORD, LPWSTR, LPWSTR, LPWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
    return ((Func)p_VerFindFileW)(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen);
}

extern "C" __declspec(dllexport) DWORD WINAPI VerInstallFileA(DWORD uFlags, LPSTR szSrcFileName, LPSTR szDestFileName, LPSTR szSrcDir, LPSTR szDestDir, LPSTR szCurDir, LPSTR szTmpFile, PUINT puTmpFileLen) {
    typedef DWORD(WINAPI* Func)(DWORD, LPSTR, LPSTR, LPSTR, LPSTR, LPSTR, LPSTR, PUINT);
    return ((Func)p_VerInstallFileA)(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen);
}

extern "C" __declspec(dllexport) DWORD WINAPI VerInstallFileW(DWORD uFlags, LPWSTR szSrcFileName, LPWSTR szDestFileName, LPWSTR szSrcDir, LPWSTR szDestDir, LPWSTR szCurDir, LPWSTR szTmpFile, PUINT puTmpFileLen) {
    typedef DWORD(WINAPI* Func)(DWORD, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, PUINT);
    return ((Func)p_VerInstallFileW)(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen);
}

extern "C" __declspec(dllexport) DWORD WINAPI VerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD cchLang) {
    typedef DWORD(WINAPI* Func)(DWORD, LPSTR, DWORD);
    return ((Func)p_VerLanguageNameA)(wLang, szLang, cchLang);
}

extern "C" __declspec(dllexport) DWORD WINAPI VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD cchLang) {
    typedef DWORD(WINAPI* Func)(DWORD, LPWSTR, DWORD);
    return ((Func)p_VerLanguageNameW)(wLang, szLang, cchLang);
}

// GetFileVersionInfoByHandle is undocumented but sometimes used
extern "C" __declspec(dllexport) int WINAPI GetFileVersionInfoByHandle(DWORD dwHandle, LPVOID lpData) {
    typedef int(WINAPI* Func)(DWORD, LPVOID);
    if (!p_GetFileVersionInfoByHandle) return 0;
    return ((Func)p_GetFileVersionInfoByHandle)(dwHandle, lpData);
}

#else
// 32-bit would use different approach - not needed for this x64 game
#error "This proxy is designed for 64-bit builds only"
#endif
