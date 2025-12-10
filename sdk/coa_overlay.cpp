/**
 * COA Script Extender - In-Game Overlay Implementation
 * 
 * Uses D3D11 hooking to render text overlay on the game screen.
 * Falls back to a transparent window overlay if D3D hook fails.
 */

#include "coa_overlay.h"
#include "coa_hooks.h"
#include "coa_sdk.h"
#include <windows.h>
#include <d3d11.h>
#include <string>
#include <mutex>

// Forward declaration for logging
extern void Log(const char* format, ...);

namespace COA {
namespace Overlay {

//=============================================================================
// STATE
//=============================================================================

static bool g_Initialized = false;
static bool g_Enabled = true;
static std::string g_Text = "COA Script Extender v" COA_VERSION;
static float g_PosX = 0.01f;  // Top-left corner
static float g_PosY = 0.01f;
static int g_ColorR = 0;
static int g_ColorG = 255;
static int g_ColorB = 100;
static std::mutex g_Mutex;

// D3D11 hook state
static bool g_D3DHooked = false;

// Windows overlay state
static HWND g_OverlayWnd = nullptr;
static bool g_UseWindowOverlay = false;

// D3D11 function pointers
typedef HRESULT(WINAPI* Present_t)(IDXGISwapChain* swapChain, UINT syncInterval, UINT flags);
static Present_t g_OriginalPresent = nullptr;

//=============================================================================
// D3D11 HOOK APPROACH
//=============================================================================

// Hook for IDXGISwapChain::Present
static HRESULT WINAPI Hooked_Present(IDXGISwapChain* swapChain, UINT syncInterval, UINT flags) {
    // TODO: Render overlay text here using D3D11
    // This requires setting up a D3D11 text rendering pipeline
    // For now, we use the simpler window overlay approach
    
    return g_OriginalPresent(swapChain, syncInterval, flags);
}

static bool HookD3D11() {
    // Get the DXGI module
    HMODULE dxgi = GetModuleHandleA("dxgi.dll");
    if (!dxgi) {
        Log("[Overlay] dxgi.dll not loaded yet");
        return false;
    }
    
    // For D3D11 hooking, we need to:
    // 1. Create a dummy window and D3D11 device
    // 2. Get the vtable of IDXGISwapChain
    // 3. Hook the Present function
    
    // This is complex, so we'll use the window overlay for now
    Log("[Overlay] D3D11 hooking not implemented, using window overlay");
    return false;
}

//=============================================================================
// WINDOW OVERLAY APPROACH
//=============================================================================

static LRESULT CALLBACK OverlayWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            if (g_Enabled) {
                // Set up text rendering
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, RGB(g_ColorR, g_ColorG, g_ColorB));
                
                // Create font
                HFONT hFont = CreateFontA(
                    16,             // Height
                    0,              // Width (0 = auto)
                    0,              // Escapement
                    0,              // Orientation
                    FW_BOLD,        // Weight
                    FALSE,          // Italic
                    FALSE,          // Underline
                    FALSE,          // StrikeOut
                    DEFAULT_CHARSET,
                    OUT_DEFAULT_PRECIS,
                    CLIP_DEFAULT_PRECIS,
                    ANTIALIASED_QUALITY,
                    DEFAULT_PITCH | FF_DONTCARE,
                    "Consolas"
                );
                
                HFONT oldFont = (HFONT)SelectObject(hdc, hFont);
                
                // Draw text
                std::lock_guard<std::mutex> lock(g_Mutex);
                TextOutA(hdc, 10, 10, g_Text.c_str(), (int)g_Text.length());
                
                SelectObject(hdc, oldFont);
                DeleteObject(hFont);
            }
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        
        case WM_DESTROY:
            g_OverlayWnd = nullptr;
            return 0;
    }
    
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static DWORD WINAPI OverlayThread(LPVOID param) {
    // Find game window
    HWND gameWnd = nullptr;
    for (int i = 0; i < 100 && !gameWnd; i++) {
        gameWnd = FindWindowA(nullptr, "Call to Arms");
        if (!gameWnd) gameWnd = FindWindowA(nullptr, "Gates of Hell");
        if (!gameWnd) gameWnd = FindWindowA("call_to_arms", nullptr);
        if (!gameWnd) Sleep(100);
    }
    
    if (!gameWnd) {
        Log("[Overlay] Could not find game window");
        return 1;
    }
    
    Log("[Overlay] Found game window: 0x%p", gameWnd);
    
    // Get game window position
    RECT gameRect;
    GetWindowRect(gameWnd, &gameRect);
    
    // Register overlay window class
    WNDCLASSA wc = {};
    wc.lpfnWndProc = OverlayWndProc;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.lpszClassName = "COA_Overlay";
    wc.hbrBackground = (HBRUSH)GetStockObject(NULL_BRUSH);
    
    if (!RegisterClassA(&wc)) {
        DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            Log("[Overlay] Failed to register window class: %d", err);
            return 1;
        }
    }
    
    // Create transparent overlay window
    g_OverlayWnd = CreateWindowExA(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        "COA_Overlay",
        "COA Script Extender Overlay",
        WS_POPUP,
        gameRect.left + 10,
        gameRect.top + 30,
        400,
        50,
        nullptr,
        nullptr,
        GetModuleHandleA(nullptr),
        nullptr
    );
    
    if (!g_OverlayWnd) {
        Log("[Overlay] Failed to create overlay window: %d", GetLastError());
        return 1;
    }
    
    // Set transparency
    SetLayeredWindowAttributes(g_OverlayWnd, RGB(0, 0, 0), 0, LWA_COLORKEY);
    
    // Show window
    ShowWindow(g_OverlayWnd, SW_SHOWNOACTIVATE);
    UpdateWindow(g_OverlayWnd);
    
    Log("[Overlay] Overlay window created");
    
    // Message loop
    MSG msg;
    while (GetMessageA(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
        
        // Update position to follow game window
        if (IsWindow(gameWnd)) {
            GetWindowRect(gameWnd, &gameRect);
            SetWindowPos(g_OverlayWnd, HWND_TOPMOST, 
                gameRect.left + 10, gameRect.top + 30, 
                0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
        }
        
        // Repaint periodically
        InvalidateRect(g_OverlayWnd, nullptr, TRUE);
    }
    
    return 0;
}

static bool CreateWindowOverlay() {
    // Create overlay on a separate thread
    HANDLE thread = CreateThread(nullptr, 0, OverlayThread, nullptr, 0, nullptr);
    if (!thread) {
        Log("[Overlay] Failed to create overlay thread");
        return false;
    }
    
    g_UseWindowOverlay = true;
    Log("[Overlay] Window overlay thread started");
    return true;
}

//=============================================================================
// SIMPLE LOG-BASED "OVERLAY" (fallback)
//=============================================================================

// If all else fails, we just log that we're active
// The user can check the log file
static void SimpleIndicator() {
    Log("[Overlay] ==========================================");
    Log("[Overlay]  COA SCRIPT EXTENDER v%s ACTIVE", COA_VERSION);
    Log("[Overlay] ==========================================");
}

//=============================================================================
// PUBLIC API
//=============================================================================

bool Initialize() {
    if (g_Initialized) return true;
    
    Log("[Overlay] Initializing overlay...");
    
    // Try D3D11 hook first (best integration)
    if (HookD3D11()) {
        g_D3DHooked = true;
        g_Initialized = true;
        Log("[Overlay] Using D3D11 hook overlay");
        return true;
    }
    
    // Try window overlay (works on Wine/Proton too)
    // Disabled by default as it can be intrusive
    // if (CreateWindowOverlay()) {
    //     g_Initialized = true;
    //     Log("[Overlay] Using window overlay");
    //     return true;
    // }
    
    // Fall back to log-based indicator
    SimpleIndicator();
    g_Initialized = true;
    Log("[Overlay] Using log-based indicator (overlay disabled)");
    return true;
}

void Shutdown() {
    if (!g_Initialized) return;
    
    if (g_OverlayWnd) {
        PostMessageA(g_OverlayWnd, WM_CLOSE, 0, 0);
        g_OverlayWnd = nullptr;
    }
    
    g_Initialized = false;
    Log("[Overlay] Shutdown complete");
}

void SetEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(g_Mutex);
    g_Enabled = enabled;
    
    if (g_OverlayWnd) {
        ShowWindow(g_OverlayWnd, enabled ? SW_SHOWNOACTIVATE : SW_HIDE);
    }
}

bool IsEnabled() {
    return g_Enabled;
}

void SetText(const char* text) {
    std::lock_guard<std::mutex> lock(g_Mutex);
    g_Text = text ? text : "";
    
    if (g_OverlayWnd) {
        InvalidateRect(g_OverlayWnd, nullptr, TRUE);
    }
}

void SetPosition(float x, float y) {
    std::lock_guard<std::mutex> lock(g_Mutex);
    g_PosX = x;
    g_PosY = y;
}

void SetColor(int r, int g, int b) {
    std::lock_guard<std::mutex> lock(g_Mutex);
    g_ColorR = r;
    g_ColorG = g;
    g_ColorB = b;
    
    if (g_OverlayWnd) {
        InvalidateRect(g_OverlayWnd, nullptr, TRUE);
    }
}

} // namespace Overlay
} // namespace COA
