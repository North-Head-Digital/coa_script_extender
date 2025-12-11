/**
 * Example Mod for COA Script Extender
 * 
 * This demonstrates how to create a mod using the Plugin API.
 * Place compiled DLL in the "mods" folder next to the game executable.
 * 
 * FEATURES DEMONSTRATED:
 * 1. Registering custom Lua functions (accessible from game scripts!)
 * 2. Registering namespaced Lua functions
 * 3. Subscribing to game events
 * 4. Hooking game functions directly
 * 5. Using the Lua API to interact with the game's scripting engine
 * 
 * USAGE IN LUA:
 *   -- Core plugin functions appear in COA_Extender
 *   COA_Extender.ExampleFunction(42, "hello")
 *   local result = COA_Extender.AddNumbers(10, 20)  -- returns 30
 *   
 *   -- Namespaced functions appear in COA_Plugins
 *   local version = COA_Plugins.ExampleMod.GetModVersion()
 */

#include "coa_sdk.h"
#include "coa_hooks.h"
#include "coa_plugin_api.h"
#include <windows.h>
#include <stdio.h>
#include "MinHook.h"

// Game base address (defined in this mod, set at init)
uintptr_t g_GameBase = 0;

// Store the Plugin API for later use
static const COA_PluginAPI* g_API = nullptr;
static const COA_LuaAPI* g_Lua = nullptr;

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
// CUSTOM LUA FUNCTIONS
// These will be callable from Lua scripts!
//=============================================================================

/**
 * COA_Extender.ExampleFunction(num, str)
 * 
 * A simple example function that logs its arguments.
 * Shows how to read arguments from the Lua stack.
 */
static int LuaFunc_ExampleFunction(lua_State* L) {
    if (!g_Lua) return 0;
    
    // Read arguments from Lua stack (1-indexed)
    int arg1 = (int)g_Lua->lua_tointeger(L, 1);
    const char* arg2 = g_Lua->lua_tostring(L, 2);
    
    ModLog("ExampleFunction called! arg1=%d, arg2=%s", arg1, arg2 ? arg2 : "(null)");
    
    // Return nothing
    return 0;
}

/**
 * COA_Extender.AddNumbers(a, b) -> number
 * 
 * Adds two numbers together. Shows how to return values.
 */
static int LuaFunc_AddNumbers(lua_State* L) {
    if (!g_Lua) return 0;
    
    lua_Number a = g_Lua->lua_tonumber(L, 1);
    lua_Number b = g_Lua->lua_tonumber(L, 2);
    lua_Number result = a + b;
    
    ModLog("AddNumbers(%f, %f) = %f", a, b, result);
    
    // Push result onto stack and return 1 (number of return values)
    g_Lua->lua_pushnumber(L, result);
    return 1;
}

/**
 * COA_Extender.MultiplyDamage(amount) -> number
 * 
 * Applies the mod's damage multiplier to a value.
 */
static int LuaFunc_MultiplyDamage(lua_State* L) {
    if (!g_Lua) return 0;
    
    lua_Number damage = g_Lua->lua_tonumber(L, 1);
    lua_Number result = damage * g_Config.damageMultiplier;
    
    g_Lua->lua_pushnumber(L, result);
    return 1;
}

/**
 * COA_Extender.SetDamageMultiplier(mult)
 * 
 * Sets the mod's damage multiplier.
 */
static int LuaFunc_SetDamageMultiplier(lua_State* L) {
    if (!g_Lua) return 0;
    
    g_Config.damageMultiplier = (float)g_Lua->lua_tonumber(L, 1);
    ModLog("Damage multiplier set to %f", g_Config.damageMultiplier);
    
    return 0;
}

/**
 * COA_Extender.GetDamageMultiplier() -> number
 * 
 * Gets the current damage multiplier.
 */
static int LuaFunc_GetDamageMultiplier(lua_State* L) {
    if (!g_Lua) return 0;
    
    g_Lua->lua_pushnumber(L, g_Config.damageMultiplier);
    return 1;
}

/**
 * COA_Plugins.ExampleMod.GetModVersion() -> string
 * 
 * A namespaced function - appears under COA_Plugins.ExampleMod
 */
static int LuaFunc_GetModVersion(lua_State* L) {
    if (!g_Lua) return 0;
    
    g_Lua->lua_pushstring(L, "1.0.0");
    return 1;
}

/**
 * COA_Plugins.ExampleMod.GetConfig() -> table
 * 
 * Returns the mod's config as a Lua table.
 * Demonstrates creating Lua tables from C++.
 */
static int LuaFunc_GetConfig(lua_State* L) {
    if (!g_Lua) return 0;
    
    // Create a table
    g_Lua->lua_createtable(L, 0, 3);
    
    // table.damageMultiplier = value
    g_Lua->lua_pushnumber(L, g_Config.damageMultiplier);
    g_Lua->lua_setfield(L, -2, "damageMultiplier");
    
    // table.accuracyBonus = value
    g_Lua->lua_pushnumber(L, g_Config.accuracyBonus);
    g_Lua->lua_setfield(L, -2, "accuracyBonus");
    
    // table.logDamage = value
    g_Lua->lua_pushboolean(L, g_Config.logDamage ? 1 : 0);
    g_Lua->lua_setfield(L, -2, "logDamage");
    
    // Table is at top of stack, return 1 value
    return 1;
}

//=============================================================================
// EVENT HANDLERS
//=============================================================================

/**
 * Called every game tick.
 */
static bool OnTick(const COA_EventData* data) {
    // data->tick.deltaTime has the frame delta time
    // We could do something every frame here
    return true;  // Continue processing
}

/**
 * Called when Lua state becomes available.
 */
static bool OnLuaLoaded(const COA_EventData* data) {
    ModLog("Lua state loaded! L=%p", data->lua.state);
    return true;
}

//=============================================================================
// HOOKS (Direct game function hooking)
//=============================================================================

typedef void* (*ParseDamageStats_t)(void*, void*, void*);
static ParseDamageStats_t OriginalParseDamageStats = nullptr;

void* HookedParseDamageStats(void* p1, void* p2, void* p3) {
    if (g_Config.logDamage) {
        ModLog("ParseDamageStats: p1=%p, p2=%p, p3=%p", p1, p2, p3);
    }
    return OriginalParseDamageStats(p1, p2, p3);
}

typedef void (*AIUpdate_t)(void*, float);
static AIUpdate_t OriginalAIUpdate = nullptr;
static int g_AIUpdateCount = 0;

void HookedAIUpdate(void* ai, float dt) {
    g_AIUpdateCount++;
    if (g_AIUpdateCount % 10000 == 0) {
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

/**
 * Called when the mod is loaded.
 * Receives the Plugin API table - store it for later use!
 */
__declspec(dllexport) bool ModInit(const COA_PluginAPI* api) {
    // Store the API for later use
    g_API = api;
    
    // Get game base
    g_GameBase = api->GetGameBase();
    
    // Get the Lua API
    g_Lua = api->GetLuaAPI();
    
    // Open log file
    char logPath[MAX_PATH];
    GetModuleFileNameA(nullptr, logPath, MAX_PATH);
    char* slash = strrchr(logPath, '\\');
    if (slash) strcpy(slash + 1, "mods\\example_mod.log");
    
    g_ModLog = fopen(logPath, "w");
    if (g_ModLog) {
        ModLog("=== Example Mod Init ===");
        ModLog("Game base: 0x%llX", g_GameBase);
        ModLog("Plugin API: v%u, size=%u", api->version, api->size);
        ModLog("Lua API: %p", g_Lua);
    }
    
    //=========================================================================
    // REGISTER LUA FUNCTIONS
    // These will be accessible from Lua scripts!
    //=========================================================================
    
    // Functions in COA_Extender (global namespace)
    api->RegisterLuaFunction("ExampleFunction", LuaFunc_ExampleFunction);
    api->RegisterLuaFunction("AddNumbers", LuaFunc_AddNumbers);
    api->RegisterLuaFunction("MultiplyDamage", LuaFunc_MultiplyDamage);
    api->RegisterLuaFunction("SetDamageMultiplier", LuaFunc_SetDamageMultiplier);
    api->RegisterLuaFunction("GetDamageMultiplier", LuaFunc_GetDamageMultiplier);
    
    // Namespaced functions in COA_Plugins.ExampleMod
    api->RegisterNamespacedFunction("ExampleMod", "GetModVersion", LuaFunc_GetModVersion);
    api->RegisterNamespacedFunction("ExampleMod", "GetConfig", LuaFunc_GetConfig);
    
    ModLog("Registered 7 Lua functions");
    
    //=========================================================================
    // SUBSCRIBE TO EVENTS
    //=========================================================================
    
    api->SubscribeEvent(COA_EVENT_TICK, OnTick);
    api->SubscribeEvent(COA_EVENT_LUA_LOADED, OnLuaLoaded);
    
    ModLog("Subscribed to 2 events");
    
    //=========================================================================
    // INSTALL HOOKS (Optional - for direct game function hooking)
    //=========================================================================
    
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED) {
        ModLog("MinHook init failed: %d", status);
        return false;
    }
    
    // These hooks are examples - enable if you know the offsets are correct
    // InstallHook(COA::Hooks::PARSE_DAMAGE_STATS, (void*)HookedParseDamageStats,
    //             (void**)&OriginalParseDamageStats, "ParseDamageStats");
    // InstallHook(COA::Hooks::AI_UPDATE, (void*)HookedAIUpdate,
    //             (void**)&OriginalAIUpdate, "AIUpdate");
    
    ModLog("Example Mod initialized successfully!");
    return true;
}

/**
 * Called when the mod is unloaded.
 */
__declspec(dllexport) void ModShutdown() {
    ModLog("=== Example Mod Shutdown ===");
    
    if (OriginalParseDamageStats) 
        MH_DisableHook((void*)(g_GameBase + COA::Hooks::PARSE_DAMAGE_STATS));
    if (OriginalAIUpdate) 
        MH_DisableHook((void*)(g_GameBase + COA::Hooks::AI_UPDATE));
    
    if (g_ModLog) { 
        fclose(g_ModLog); 
        g_ModLog = nullptr; 
    }
}

/**
 * Called every game tick.
 */
__declspec(dllexport) void ModTick(float dt) {
    // Can do per-frame updates here
}

/**
 * Returns the mod name.
 */
__declspec(dllexport) const char* ModGetName() { 
    return "Example Mod"; 
}

/**
 * Returns the mod version.
 */
__declspec(dllexport) const char* ModGetVersion() { 
    return "1.0.0"; 
}

/**
 * Returns the mod author.
 */
__declspec(dllexport) const char* ModGetAuthor() { 
    return "COA Script Extender"; 
}

}
