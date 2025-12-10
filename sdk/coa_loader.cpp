/**
 * Call to Arms: Gates of Hell - Script Extender Loader
 * 
 * DLL entry point that initializes the hook system and loads mods.
 * Uses MinHook for function detouring.
 * 
 * Build: Compile as a DLL and inject into the game process.
 */

#include "coa_sdk.h"
#include "coa_hooks.h"
#include "coa_lua_bridge.h"
#include "coa_overlay.h"

#ifdef _WIN32
#include <windows.h>
#else
#error "This SDK only builds for Windows"
#endif

#include <stdio.h>
#include <vector>
#include <string>
#include <filesystem>

// MinHook header (download from https://github.com/TsudaKageworst/minhook)
#include "MinHook.h"

//=============================================================================
// GLOBALS
//=============================================================================

uintptr_t g_GameBase = 0;
static HMODULE g_ModuleHandle = nullptr;
static bool g_Initialized = false;

// Mod DLL handles
static std::vector<HMODULE> g_LoadedMods;

// Log file
static FILE* g_LogFile = nullptr;

//=============================================================================
// LOGGING
//=============================================================================

void Log(const char* format, ...) {
    if (!g_LogFile) return;
    
    va_list args;
    va_start(args, format);
    
    // Timestamp
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_LogFile, "[%02d:%02d:%02d.%03d] ", 
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    
    vfprintf(g_LogFile, format, args);
    fprintf(g_LogFile, "\n");
    fflush(g_LogFile);
    
    va_end(args);
}

void InitLogging() {
    char path[MAX_PATH];
    GetModuleFileNameA(g_ModuleHandle, path, MAX_PATH);
    
    // Replace .dll with .log
    std::string logPath = path;
    size_t pos = logPath.rfind('.');
    if (pos != std::string::npos) {
        logPath = logPath.substr(0, pos) + ".log";
    } else {
        logPath += ".log";
    }
    
    g_LogFile = fopen(logPath.c_str(), "w");
    if (g_LogFile) {
        Log("=== COA Script Extender Log ===");
        Log("Log file: %s", logPath.c_str());
    }
}

void ShutdownLogging() {
    if (g_LogFile) {
        Log("=== Shutting Down ===");
        fclose(g_LogFile);
        g_LogFile = nullptr;
    }
}

//=============================================================================
// HOOK SYSTEM IMPLEMENTATION
//=============================================================================

namespace COA {
namespace Hooks {

struct HookEntry {
    uintptr_t offset;
    void* target;
    void* original;
    bool enabled;
};

static std::vector<HookEntry> g_Hooks;

bool Initialize() {
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        Log("MinHook initialization failed: %d", status);
        return false;
    }
    Log("MinHook initialized successfully");
    return true;
}

void Shutdown() {
    // Disable all hooks
    for (auto& hook : g_Hooks) {
        if (hook.enabled) {
            MH_DisableHook((LPVOID)COA_RVA(hook.offset));
        }
    }
    g_Hooks.clear();
    
    MH_Uninitialize();
    Log("MinHook shutdown");
}

bool Install(uintptr_t offset, void* hookFunction, void** originalFunction) {
    void* target = (void*)COA_RVA(offset);
    
    MH_STATUS status = MH_CreateHook(target, hookFunction, originalFunction);
    if (status != MH_OK) {
        Log("Failed to create hook at 0x%llX: %d", offset, status);
        return false;
    }
    
    status = MH_EnableHook(target);
    if (status != MH_OK) {
        Log("Failed to enable hook at 0x%llX: %d", offset, status);
        return false;
    }
    
    HookEntry entry = { offset, hookFunction, *originalFunction, true };
    g_Hooks.push_back(entry);
    
    Log("Installed hook at 0x%llX -> 0x%p", offset, hookFunction);
    return true;
}

bool Remove(uintptr_t offset) {
    void* target = (void*)COA_RVA(offset);
    
    MH_STATUS status = MH_DisableHook(target);
    if (status != MH_OK) {
        Log("Failed to disable hook at 0x%llX: %d", offset, status);
        return false;
    }
    
    status = MH_RemoveHook(target);
    if (status != MH_OK) {
        Log("Failed to remove hook at 0x%llX: %d", offset, status);
        return false;
    }
    
    // Remove from our list
    for (auto it = g_Hooks.begin(); it != g_Hooks.end(); ++it) {
        if (it->offset == offset) {
            g_Hooks.erase(it);
            break;
        }
    }
    
    Log("Removed hook at 0x%llX", offset);
    return true;
}

bool IsInstalled(uintptr_t offset) {
    for (const auto& hook : g_Hooks) {
        if (hook.offset == offset) return true;
    }
    return false;
}

void SetEnabled(uintptr_t offset, bool enabled) {
    void* target = (void*)COA_RVA(offset);
    
    if (enabled) {
        MH_EnableHook(target);
    } else {
        MH_DisableHook(target);
    }
    
    for (auto& hook : g_Hooks) {
        if (hook.offset == offset) {
            hook.enabled = enabled;
            break;
        }
    }
}

void* GetOriginal(uintptr_t offset) {
    for (const auto& hook : g_Hooks) {
        if (hook.offset == offset) return hook.original;
    }
    return nullptr;
}

} // namespace Hooks
} // namespace COA

//=============================================================================
// GAME WORLD ACCESSORS (Stubs - need actual game analysis to implement)
//=============================================================================

namespace COA {

// These need to be filled in with actual game pointers once found
static GameWorld* g_GameWorld = nullptr;

GameWorld* GetGameWorld() {
    // TODO: Find the actual game world singleton
    // This is typically a global pointer like:
    // return *(GameWorld**)(g_GameBase + GAME_WORLD_OFFSET);
    return g_GameWorld;
}

Team* GetPlayerTeam() {
    GameWorld* world = GetGameWorld();
    if (!world || world->teamCount == 0) return nullptr;
    return world->teams[0]; // Usually player is team 0
}

Unit* GetUnitById(uint64_t id) {
    GameWorld* world = GetGameWorld();
    if (!world) return nullptr;
    
    for (int i = 0; i < world->unitCount; i++) {
        if (world->allUnits[i] && world->allUnits[i]->entityId == id) {
            return world->allUnits[i];
        }
    }
    return nullptr;
}

Vehicle* GetVehicleById(uint64_t id) {
    GameWorld* world = GetGameWorld();
    if (!world) return nullptr;
    
    for (int i = 0; i < world->vehicleCount; i++) {
        if (world->allVehicles[i] && world->allVehicles[i]->entityId == id) {
            return world->allVehicles[i];
        }
    }
    return nullptr;
}

void ForEachUnit(UnitCallback callback, void* userData) {
    GameWorld* world = GetGameWorld();
    if (!world) return;
    
    for (int i = 0; i < world->unitCount; i++) {
        if (world->allUnits[i]) {
            callback(world->allUnits[i], userData);
        }
    }
}

void ForEachVehicle(VehicleCallback callback, void* userData) {
    GameWorld* world = GetGameWorld();
    if (!world) return;
    
    for (int i = 0; i < world->vehicleCount; i++) {
        if (world->allVehicles[i]) {
            callback(world->allVehicles[i], userData);
        }
    }
}

} // namespace COA

//=============================================================================
// MOD LOADING
//=============================================================================

typedef bool (*ModInitFunc)(void);
typedef void (*ModShutdownFunc)(void);

// Steam Workshop App ID for Gates of Hell
static const char* STEAM_APP_ID = "400750";

static void LoadModsFromDirectory(const std::string& modsDir, const char* source) {
    if (!std::filesystem::exists(modsDir)) {
        return;
    }
    
    Log("Scanning %s: %s", source, modsDir.c_str());
    
    // Load all DLLs in the directory
    for (const auto& entry : std::filesystem::directory_iterator(modsDir)) {
        if (entry.path().extension() == ".dll") {
            std::string dllPath = entry.path().string();
            Log("Loading mod: %s", dllPath.c_str());
            
            HMODULE modHandle = LoadLibraryA(dllPath.c_str());
            if (!modHandle) {
                Log("Failed to load mod: %s (error %d)", dllPath.c_str(), GetLastError());
                continue;
            }
            
            // Look for ModInit function
            ModInitFunc initFunc = (ModInitFunc)GetProcAddress(modHandle, "ModInit");
            if (initFunc) {
                Log("Calling ModInit for %s", entry.path().filename().string().c_str());
                if (!initFunc()) {
                    Log("ModInit returned false, unloading");
                    FreeLibrary(modHandle);
                    continue;
                }
            }
            
            g_LoadedMods.push_back(modHandle);
            Log("Successfully loaded mod: %s", entry.path().filename().string().c_str());
        }
    }
}

static void ScanWorkshopMods(const std::string& basePath) {
    // Workshop content is typically at:
    // steamapps/workshop/content/[app_id]/[mod_id]/
    // We look for extender_mod.dll in each workshop mod folder
    
    std::string workshopBase = basePath;
    
    // Navigate from game folder to workshop folder
    // basePath = .../steamapps/common/Call to Arms - Gates of Hell/binaries/x64
    // Workshop = .../steamapps/workshop/content/400750/
    
    size_t pos = workshopBase.find("steamapps");
    if (pos == std::string::npos) {
        Log("Could not find steamapps in path, skipping Workshop scan");
        return;
    }
    
    workshopBase = workshopBase.substr(0, pos) + "steamapps\\workshop\\content\\" + STEAM_APP_ID;
    
    if (!std::filesystem::exists(workshopBase)) {
        Log("No Workshop content folder found at: %s", workshopBase.c_str());
        return;
    }
    
    Log("Scanning Steam Workshop: %s", workshopBase.c_str());
    
    // Iterate through each workshop mod folder
    for (const auto& modFolder : std::filesystem::directory_iterator(workshopBase)) {
        if (!modFolder.is_directory()) continue;
        
        // Look for extender_mod.dll in this workshop mod
        std::string extenderDll = modFolder.path().string() + "\\extender_mod.dll";
        if (std::filesystem::exists(extenderDll)) {
            Log("Found Workshop extender mod: %s", extenderDll.c_str());
            
            HMODULE modHandle = LoadLibraryA(extenderDll.c_str());
            if (!modHandle) {
                Log("Failed to load Workshop mod: %s (error %d)", extenderDll.c_str(), GetLastError());
                continue;
            }
            
            ModInitFunc initFunc = (ModInitFunc)GetProcAddress(modHandle, "ModInit");
            if (initFunc) {
                Log("Calling ModInit for Workshop mod %s", modFolder.path().filename().string().c_str());
                if (!initFunc()) {
                    Log("ModInit returned false, unloading");
                    FreeLibrary(modHandle);
                    continue;
                }
            }
            
            g_LoadedMods.push_back(modHandle);
            Log("Successfully loaded Workshop mod: %s", modFolder.path().filename().string().c_str());
        }
    }
}

void LoadMods() {
    char modPath[MAX_PATH];
    GetModuleFileNameA(g_ModuleHandle, modPath, MAX_PATH);
    
    // Get directory of the loader DLL
    std::string basePath = modPath;
    size_t pos = basePath.rfind('\\');
    if (pos != std::string::npos) {
        basePath = basePath.substr(0, pos);
    }
    
    // 1. Load from extender_mods/ folder (local mods)
    std::string localModsDir = basePath + "\\extender_mods";
    if (!std::filesystem::exists(localModsDir)) {
        Log("Creating extender_mods directory");
        std::filesystem::create_directory(localModsDir);
    }
    LoadModsFromDirectory(localModsDir, "local mods");
    
    // 2. Also check legacy "mods" folder for backwards compatibility
    std::string legacyModsDir = basePath + "\\mods";
    // Only load DLLs from mods/ if there's no resource folder (to avoid loading game's Lua mods)
    if (std::filesystem::exists(legacyModsDir)) {
        bool hasExtenderMods = false;
        for (const auto& entry : std::filesystem::directory_iterator(legacyModsDir)) {
            if (entry.path().extension() == ".dll") {
                hasExtenderMods = true;
                break;
            }
        }
        if (hasExtenderMods) {
            Log("Note: Found DLLs in mods/ folder. Consider moving to extender_mods/");
            LoadModsFromDirectory(legacyModsDir, "legacy mods folder");
        }
    }
    
    // 3. Scan Steam Workshop for extender-compatible mods
    ScanWorkshopMods(basePath);
    
    Log("Total loaded: %zu extender mods", g_LoadedMods.size());
}

void UnloadMods() {
    for (HMODULE modHandle : g_LoadedMods) {
        // Call ModShutdown if it exists
        ModShutdownFunc shutdownFunc = (ModShutdownFunc)GetProcAddress(modHandle, "ModShutdown");
        if (shutdownFunc) {
            shutdownFunc();
        }
        FreeLibrary(modHandle);
    }
    g_LoadedMods.clear();
    Log("Unloaded all mods");
}

//=============================================================================
// INITIALIZATION
//=============================================================================

bool Initialize() {
    if (g_Initialized) return true;
    
    InitLogging();
    Log("COA Script Extender initializing...");
    
    // Get game base address
    g_GameBase = (uintptr_t)GetModuleHandleA(nullptr);
    Log("Game base address: 0x%llX", g_GameBase);
    
    // Initialize hook system
    if (!COA::Hooks::Initialize()) {
        Log("Failed to initialize hook system");
        return false;
    }
    
    // Initialize Lua bridge (will hook into game's Lua when state is available)
    COA::Lua::Initialize();
    
    // Initialize overlay (shows "Script Extender Active" in-game)
    COA::Overlay::Initialize();
    
    // Load mods
    LoadMods();
    
    g_Initialized = true;
    Log("COA Script Extender initialized successfully");
    return true;
}

void Shutdown() {
    if (!g_Initialized) return;
    
    Log("COA Script Extender shutting down...");
    
    COA::Overlay::Shutdown();
    UnloadMods();
    COA::Lua::Shutdown();
    COA::Hooks::Shutdown();
    
    g_Initialized = false;
    ShutdownLogging();
}

//=============================================================================
// DLL ENTRY POINT
//=============================================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            g_ModuleHandle = hModule;
            DisableThreadLibraryCalls(hModule);
            
            // Initialize in a separate thread to avoid loader lock issues
            CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
                // Wait a bit for the game to initialize
                Sleep(2000);
                Initialize();
                return 0;
            }, nullptr, 0, nullptr);
            break;
            
        case DLL_PROCESS_DETACH:
            Shutdown();
            break;
    }
    return TRUE;
}

//=============================================================================
// EXPORTS
//=============================================================================

extern "C" {
    // Version info (renamed to avoid Windows API conflict)
    __declspec(dllexport) const char* COA_GetVersion() {
        return "1.0.0";
    }
    
    // Main init function - called by proxy DLL
    __declspec(dllexport) bool ExtenderInit() {
        return Initialize();
    }
    
    // Force initialization (can be called by injector)
    __declspec(dllexport) bool COA_ForceInit() {
        return Initialize();
    }
    
    // Get game base for external tools
    __declspec(dllexport) uintptr_t COA_GetGameBase() {
        return g_GameBase;
    }
}
