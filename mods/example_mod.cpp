/**
 * Example Mod for COA Script Extender
 * 
 * This demonstrates how to create a mod using the SDK.
 * Place compiled DLL in the "mods" folder next to coa_extender.dll
 * 
 * FEATURES DEMONSTRATED:
 * - Hooking AI Update functions
 * - Hooking damage parsing
 * - Logging game events
 * - Using discovered function addresses from Ghidra analysis
 */

#include "coa_sdk.h"
#include "coa_hooks.h"
#include <windows.h>
#include <stdio.h>
#include "MinHook.h"

// Game base address (defined in this mod, set at init)
uintptr_t g_GameBase = 0;

//=============================================================================
// CONFIGURATION
//=============================================================================

static struct {
    float damageMultiplier = 1.5f;
    float accuracyBonus = 0.1f;
    bool logDamage = true;
} g_Config;

static FILE* g_ModLog = nullptr;

void ModLog(const char* format, ...) {
    if (!g_ModLog) return;
    va_list args;
    va_start(args, format);
    vfprintf(g_ModLog, format, args);
    fprintf(g_ModLog, "\n");
    fflush(g_ModLog);
    va_end(args);
}

//=============================================================================
// HOOKS
//=============================================================================

typedef void* (*ParseDamageStats_t)(void*, void*, void*);
static ParseDamageStats_t OriginalParseDamageStats = nullptr;

void* HookedParseDamageStats(void* p1, void* p2, void* p3) {
    ModLog("ParseDamageStats: p1=%p, p2=%p, p3=%p", p1, p2, p3);
    return OriginalParseDamageStats(p1, p2, p3);
}

typedef void (*AIUpdate_t)(void*, float);
static AIUpdate_t OriginalAIUpdate = nullptr;
static int g_AIUpdateCount = 0;

void HookedAIUpdate(void* ai, float dt) {
    g_AIUpdateCount++;
    if (g_AIUpdateCount % 1000 == 0) {
        ModLog("AI Update #%d, dt=%.4f", g_AIUpdateCount, dt);
    }
    OriginalAIUpdate(ai, dt);
}

bool InstallHook(uintptr_t offset, void* hook, void** orig, const char* name) {
    void* target = (void*)(g_GameBase + offset);
    MH_STATUS status = MH_CreateHook(target, hook, orig);
    if (status != MH_OK) {
        ModLog("Create hook '%s' failed: %d", name, status);
        return false;
    }
    status = MH_EnableHook(target);
    if (status != MH_OK) {
        ModLog("Enable hook '%s' failed: %d", name, status);
        return false;
    }
    ModLog("Installed hook '%s' at 0x%llX", name, offset);
    return true;
}

//=============================================================================
// MOD ENTRY POINTS
//=============================================================================

extern "C" {

__declspec(dllexport) bool ModInit() {
    char logPath[MAX_PATH];
    GetModuleFileNameA(nullptr, logPath, MAX_PATH);
    char* slash = strrchr(logPath, '\\');
    if (slash) strcpy(slash + 1, "mods\\example_mod.log");
    
    g_ModLog = fopen(logPath, "w");
    if (g_ModLog) {
        ModLog("=== Example Mod Init ===");
    }
    
    g_GameBase = (uintptr_t)GetModuleHandleA(nullptr);
    ModLog("Game base: 0x%llX", g_GameBase);
    
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED) {
        ModLog("MinHook init failed: %d", status);
        return false;
    }
    
    InstallHook(COA::Hooks::PARSE_DAMAGE_STATS, (void*)HookedParseDamageStats,
                (void**)&OriginalParseDamageStats, "ParseDamageStats");
    InstallHook(COA::Hooks::AI_UPDATE, (void*)HookedAIUpdate,
                (void**)&OriginalAIUpdate, "AIUpdate");
    
    ModLog("Hooks installed!");
    return true;
}

__declspec(dllexport) void ModShutdown() {
    ModLog("=== Example Mod Shutdown ===");
    if (OriginalParseDamageStats) 
        MH_DisableHook((void*)(g_GameBase + COA::Hooks::PARSE_DAMAGE_STATS));
    if (OriginalAIUpdate) 
        MH_DisableHook((void*)(g_GameBase + COA::Hooks::AI_UPDATE));
    if (g_ModLog) { fclose(g_ModLog); g_ModLog = nullptr; }
}

__declspec(dllexport) void ModTick(float dt) {}
__declspec(dllexport) const char* ModGetName() { return "Example Mod"; }
__declspec(dllexport) const char* ModGetVersion() { return "1.0.0"; }
__declspec(dllexport) const char* ModGetAuthor() { return "COA Script Extender"; }

}
