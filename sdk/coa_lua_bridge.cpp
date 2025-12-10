/**
 * COA Script Extender - Lua Bridge Implementation
 * 
 * Hooks into the game's Lua 5.2 engine and registers custom functions.
 */

#include "coa_lua_bridge.h"
#include "coa_sdk.h"
#include "coa_hooks.h"
#include "MinHook.h"
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <mutex>

// Forward declaration for logging
extern void Log(const char* format, ...);

namespace COA {
namespace Lua {

//=============================================================================
// LUA 5.2 FUNCTION POINTER TYPES
//=============================================================================

// We dynamically resolve these from the game's Lua implementation
// (The game has Lua 5.2 statically linked)

typedef void (*lua_pushnil_t)(lua_State* L);
typedef void (*lua_pushnumber_t)(lua_State* L, lua_Number n);
typedef void (*lua_pushinteger_t)(lua_State* L, lua_Integer n);
typedef const char* (*lua_pushstring_t)(lua_State* L, const char* s);
typedef void (*lua_pushboolean_t)(lua_State* L, int b);
typedef void (*lua_pushcclosure_t)(lua_State* L, lua_CFunction fn, int n);
typedef void (*lua_createtable_t)(lua_State* L, int narr, int nrec);
typedef void (*lua_setfield_t)(lua_State* L, int idx, const char* k);
typedef void (*lua_setglobal_t)(lua_State* L, const char* name);
typedef void (*lua_getglobal_t)(lua_State* L, const char* name);
typedef void (*lua_settop_t)(lua_State* L, int idx);
typedef int (*lua_gettop_t)(lua_State* L);
typedef int (*lua_type_t)(lua_State* L, int idx);
typedef lua_Number (*lua_tonumberx_t)(lua_State* L, int idx, int* isnum);
typedef lua_Integer (*lua_tointegerx_t)(lua_State* L, int idx, int* isnum);
typedef const char* (*lua_tolstring_t)(lua_State* L, int idx, size_t* len);
typedef int (*lua_toboolean_t)(lua_State* L, int idx);
typedef int (*lua_rawgeti_t)(lua_State* L, int idx, int n);
typedef void (*lua_rawseti_t)(lua_State* L, int idx, int n);
typedef int (*lua_pcallk_t)(lua_State* L, int nargs, int nresults, int errfunc, int ctx, lua_CFunction k);
typedef int (*luaL_error_t)(lua_State* L, const char* fmt, ...);

// Function pointers (resolved at runtime)
static lua_pushnil_t        p_lua_pushnil = nullptr;
static lua_pushnumber_t     p_lua_pushnumber = nullptr;
static lua_pushinteger_t    p_lua_pushinteger = nullptr;
static lua_pushstring_t     p_lua_pushstring = nullptr;
static lua_pushboolean_t    p_lua_pushboolean = nullptr;
static lua_pushcclosure_t   p_lua_pushcclosure = nullptr;
static lua_createtable_t    p_lua_createtable = nullptr;
static lua_setfield_t       p_lua_setfield = nullptr;
static lua_setglobal_t      p_lua_setglobal = nullptr;
static lua_getglobal_t      p_lua_getglobal = nullptr;
static lua_settop_t         p_lua_settop = nullptr;
static lua_gettop_t         p_lua_gettop = nullptr;
static lua_type_t           p_lua_type = nullptr;
static lua_tonumberx_t      p_lua_tonumberx = nullptr;
static lua_tointegerx_t     p_lua_tointegerx = nullptr;
static lua_tolstring_t      p_lua_tolstring = nullptr;
static lua_toboolean_t      p_lua_toboolean = nullptr;
static lua_rawseti_t        p_lua_rawseti = nullptr;
static lua_pcallk_t         p_lua_pcallk = nullptr;
static luaL_error_t         p_luaL_error = nullptr;

// State tracking
static lua_State* g_LuaState = nullptr;
static bool g_Initialized = false;
static std::mutex g_LuaMutex;

// Extender settings that Lua can modify
static float g_DamageMultiplier = 1.0f;
static bool g_GodMode = false;
static bool g_UnlimitedAmmo = false;
static std::vector<std::string> g_LuaLogMessages;

//=============================================================================
// HELPER MACROS
//=============================================================================

#define lua_pop(L, n)           p_lua_settop(L, -(n)-1)
#define lua_pushcfunction(L, f) p_lua_pushcclosure(L, (f), 0)
#define lua_newtable(L)         p_lua_createtable(L, 0, 0)
#define lua_tonumber(L, i)      p_lua_tonumberx(L, (i), nullptr)
#define lua_tointeger(L, i)     p_lua_tointegerx(L, (i), nullptr)
#define lua_tostring(L, i)      p_lua_tolstring(L, (i), nullptr)
#define lua_isnil(L, n)         (p_lua_type(L, (n)) == 0)
#define lua_isnumber(L, n)      (p_lua_type(L, (n)) == 3)
#define lua_isstring(L, n)      (p_lua_type(L, (n)) == 4)
#define lua_isboolean(L, n)     (p_lua_type(L, (n)) == 1)
#define lua_pcall(L, n, r, f)   p_lua_pcallk(L, (n), (r), (f), 0, nullptr)

//=============================================================================
// LUA FUNCTION IMPLEMENTATIONS
//=============================================================================

// COA_Extender.GetVersion() -> string
static int L_GetVersion(lua_State* L) {
    p_lua_pushstring(L, COA_VERSION);
    return 1;
}

// COA_Extender.Log(message) -> nil
static int L_Log(lua_State* L) {
    const char* msg = lua_tostring(L, 1);
    if (msg) {
        Log("[Lua] %s", msg);
        g_LuaLogMessages.push_back(msg);
    }
    return 0;
}

// COA_Extender.IsActive() -> bool
static int L_IsActive(lua_State* L) {
    p_lua_pushboolean(L, 1);
    return 1;
}

// COA_Extender.GetGameBase() -> integer
static int L_GetGameBase(lua_State* L) {
    p_lua_pushinteger(L, (lua_Integer)g_GameBase);
    return 1;
}

// COA_Extender.SetDamageMultiplier(multiplier) -> nil
static int L_SetDamageMultiplier(lua_State* L) {
    if (lua_isnumber(L, 1)) {
        g_DamageMultiplier = (float)lua_tonumber(L, 1);
        Log("[Lua] Damage multiplier set to %.2f", g_DamageMultiplier);
    }
    return 0;
}

// COA_Extender.GetDamageMultiplier() -> number
static int L_GetDamageMultiplier(lua_State* L) {
    p_lua_pushnumber(L, g_DamageMultiplier);
    return 1;
}

// COA_Extender.SetGodMode(enabled) -> nil
static int L_SetGodMode(lua_State* L) {
    if (lua_isboolean(L, 1)) {
        g_GodMode = p_lua_toboolean(L, 1) != 0;
        Log("[Lua] God mode %s", g_GodMode ? "enabled" : "disabled");
    }
    return 0;
}

// COA_Extender.IsGodMode() -> bool
static int L_IsGodMode(lua_State* L) {
    p_lua_pushboolean(L, g_GodMode ? 1 : 0);
    return 1;
}

// COA_Extender.SetUnlimitedAmmo(enabled) -> nil
static int L_SetUnlimitedAmmo(lua_State* L) {
    if (lua_isboolean(L, 1)) {
        g_UnlimitedAmmo = p_lua_toboolean(L, 1) != 0;
        Log("[Lua] Unlimited ammo %s", g_UnlimitedAmmo ? "enabled" : "disabled");
    }
    return 0;
}

// COA_Extender.IsUnlimitedAmmo() -> bool
static int L_IsUnlimitedAmmo(lua_State* L) {
    p_lua_pushboolean(L, g_UnlimitedAmmo ? 1 : 0);
    return 1;
}

// COA_Extender.GetLoadedMods() -> table of strings
static int L_GetLoadedMods(lua_State* L) {
    // TODO: Return list of loaded extender mods
    // For now, return an empty table (will be filled when Lua functions are resolved)
    lua_newtable(L);
    // Once resolved: p_lua_pushstring(L, "example_mod"); p_lua_rawseti(L, -2, 1);
    return 1;
}

// COA_Extender.ExecuteHook(hookName, ...) -> varies
// Allows Lua mods to trigger custom hooks
static int L_ExecuteHook(lua_State* L) {
    const char* hookName = lua_tostring(L, 1);
    if (hookName) {
        Log("[Lua] ExecuteHook called: %s", hookName);
        // TODO: Dispatch to registered hook handlers
    }
    return 0;
}

//=============================================================================
// KNOWN OFFSETS (from Ghidra analysis via FindLuaAPIs.java)
//=============================================================================

// Game's lua.start initialization handler
#define LUA_START_HANDLER_OFFSET    0x004BA470

// === LUA STATE CREATION (from AnalyzeLuaInitCaller.java) ===
// FUN_140d6cfa0 is called first in both Lua init functions, returns lua_State* in RAX
#define LUA_NEWSTATE_OFFSET         0x00D6CFA0  // lua_newstate or luaL_newstate

// Global variable that stores lua_State* (from AnalyzeLuaInitCaller.java)
// 0x01139B48 is used as RCX (first param) in multiple Lua calls
#define LUA_STATE_GLOBAL_OFFSET     0x01139B48  // Global lua_State* storage

// === CORE LUA 5.2 API FUNCTIONS ===

// Stack manipulation
#define LUA_SETTOP_OFFSET           0x00D6F090  // lua_settop (for lua_pop)
#define LUA_TYPE_OFFSET             0x00D6F630  // lua_type

// Push functions
#define LUA_PUSHSTRING_OFFSET       0x00D7AC60  // lua_pushstring
#define LUA_PUSHCCLOSURE_OFFSET     0x00D6AB20  // lua_pushcclosure - VERIFIED via Ghidra
#define LUAL_SETFUNCS_OFFSET        0x00D6E580  // luaL_setfuncs (was incorrectly labeled pushcclosure)
#define LUA_PUSHFSTRING_OFFSET      0x00D6D0C0  // lua_pushfstring

// Table functions
#define LUA_CREATETABLE_OFFSET      0x00D77E80  // lua_createtable (for lua_newtable)
#define LUA_SETFIELD_OFFSET         0x00D76D50  // lua_setfield

// Call functions
#define LUA_PCALL_OFFSET            0x00D712A0  // lua_pcall
#define LUA_ERROR_OFFSET            0x00D715C0  // lua_error

// Error handling
#define LUAL_ERROR_OFFSET           0x00D6CCF0  // luaL_error

// Loading
#define LUAL_LOADFILE_OFFSET        0x00D6DB50  // luaL_loadfile
#define LUAL_LOADBUFFER_OFFSET      0x00D7D2E0  // luaL_loadbuffer

// Library opening
#define LUAL_OPENLIBS_OFFSET        0x00D85F90  // luaL_openlibs

// === DISCOVERED VIA FindLuaSetGlobal.java + VerifyLuaFunctions.java ===
// lua_setglobal at 0x00D773F0 (274 bytes, calls lua_setfield)
#define LUA_SETGLOBAL_OFFSET        0x00D773F0  // lua_setglobal

// Push functions near lua_pushstring (0x00D7AC60) - VERIFIED via instruction analysis:
// 0x00D7A440 uses ECX (integer param) -> lua_pushinteger
// 0x00D7A470 uses XMM0 (double param) -> lua_pushnumber
#define LUA_PUSHINTEGER_OFFSET      0x00D7A440  // lua_pushinteger (48 bytes, uses ECX)
#define LUA_PUSHNUMBER_OFFSET       0x00D7A470  // lua_pushnumber (50 bytes, uses XMM0)

// lua_pushboolean - need to find separately (different signature)
// Looking at 0x00D6F6D0 (70 bytes) or similar small functions
#define LUA_PUSHBOOLEAN_OFFSET      0x00D7A4B0  // lua_pushboolean candidate (127 bytes)

// Stack query - VERIFIED: 0x00D6FD10 is 16 bytes, perfect for lua_gettop
#define LUA_GETTOP_OFFSET           0x00D6FD10  // lua_gettop (16 bytes)

// lua_to* functions - in range 0x00D6F200 - 0x00D6F800
#define LUA_TOBOOLEAN_OFFSET        0x00D6F550  // lua_toboolean (118 bytes)
#define LUA_TONUMBERX_OFFSET        0x00D6F3D0  // lua_tonumberx (380 bytes)
#define LUA_TOLSTRING_OFFSET        0x00D7A290  // lua_tolstring (336 bytes, near pushstring)

//=============================================================================
// FUNCTION RESOLVER
//=============================================================================

// Find Lua functions by scanning for known patterns
static bool ResolveLuaFunctions() {
    // The game has Lua statically linked
    uintptr_t base = g_GameBase;
    
    Log("[LuaBridge] Resolving Lua functions from game base 0x%llX", base);
    
    // === STACK MANIPULATION ===
    p_lua_settop = (lua_settop_t)(base + LUA_SETTOP_OFFSET);
    Log("[LuaBridge] lua_settop at 0x%llX", (uintptr_t)p_lua_settop);
    
    p_lua_gettop = (lua_gettop_t)(base + LUA_GETTOP_OFFSET);
    Log("[LuaBridge] lua_gettop at 0x%llX (guessed)", (uintptr_t)p_lua_gettop);
    
    p_lua_type = (lua_type_t)(base + LUA_TYPE_OFFSET);
    Log("[LuaBridge] lua_type at 0x%llX", (uintptr_t)p_lua_type);
    
    // === PUSH FUNCTIONS ===
    p_lua_pushstring = (lua_pushstring_t)(base + LUA_PUSHSTRING_OFFSET);
    Log("[LuaBridge] lua_pushstring at 0x%llX", (uintptr_t)p_lua_pushstring);
    
    p_lua_pushcclosure = (lua_pushcclosure_t)(base + LUA_PUSHCCLOSURE_OFFSET);
    Log("[LuaBridge] lua_pushcclosure at 0x%llX", (uintptr_t)p_lua_pushcclosure);
    
    // === TABLE FUNCTIONS ===
    p_lua_createtable = (lua_createtable_t)(base + LUA_CREATETABLE_OFFSET);
    Log("[LuaBridge] lua_createtable at 0x%llX", (uintptr_t)p_lua_createtable);
    
    p_lua_setfield = (lua_setfield_t)(base + LUA_SETFIELD_OFFSET);
    Log("[LuaBridge] lua_setfield at 0x%llX", (uintptr_t)p_lua_setfield);
    
    // === CALL/ERROR FUNCTIONS ===
    p_lua_pcallk = (lua_pcallk_t)(base + LUA_PCALL_OFFSET);
    Log("[LuaBridge] lua_pcall at 0x%llX", (uintptr_t)p_lua_pcallk);
    
    p_luaL_error = (luaL_error_t)(base + LUAL_ERROR_OFFSET);
    Log("[LuaBridge] luaL_error at 0x%llX", (uintptr_t)p_luaL_error);
    
    // === NEWLY DISCOVERED FUNCTIONS ===
    p_lua_setglobal = (lua_setglobal_t)(base + LUA_SETGLOBAL_OFFSET);
    Log("[LuaBridge] lua_setglobal at 0x%llX", (uintptr_t)p_lua_setglobal);
    
    p_lua_gettop = (lua_gettop_t)(base + LUA_GETTOP_OFFSET);
    Log("[LuaBridge] lua_gettop at 0x%llX", (uintptr_t)p_lua_gettop);
    
    p_lua_pushnumber = (lua_pushnumber_t)(base + LUA_PUSHNUMBER_OFFSET);
    Log("[LuaBridge] lua_pushnumber at 0x%llX", (uintptr_t)p_lua_pushnumber);
    
    p_lua_pushinteger = (lua_pushinteger_t)(base + LUA_PUSHINTEGER_OFFSET);
    Log("[LuaBridge] lua_pushinteger at 0x%llX", (uintptr_t)p_lua_pushinteger);
    
    p_lua_pushboolean = (lua_pushboolean_t)(base + LUA_PUSHBOOLEAN_OFFSET);
    Log("[LuaBridge] lua_pushboolean at 0x%llX", (uintptr_t)p_lua_pushboolean);
    
    p_lua_toboolean = (lua_toboolean_t)(base + LUA_TOBOOLEAN_OFFSET);
    Log("[LuaBridge] lua_toboolean at 0x%llX", (uintptr_t)p_lua_toboolean);
    
    p_lua_tonumberx = (lua_tonumberx_t)(base + LUA_TONUMBERX_OFFSET);
    Log("[LuaBridge] lua_tonumberx at 0x%llX", (uintptr_t)p_lua_tonumberx);
    
    p_lua_tolstring = (lua_tolstring_t)(base + LUA_TOLSTRING_OFFSET);
    Log("[LuaBridge] lua_tolstring at 0x%llX", (uintptr_t)p_lua_tolstring);
    
    Log("[LuaBridge] All Lua functions resolved!");
    Log("[LuaBridge] Ready to register COA_Extender table");
    
    return true;
}

//=============================================================================
// HOOK INTO LUA INITIALIZATION
//=============================================================================

static bool g_COAExtenderRegistered = false;
static bool g_ReadyToRegister = false;  // Flag set when we should register on next safe opportunity

// === APPROACH 0: Hook lua_pushcclosure - called when registering C functions in Lua ===
// Signature: void lua_pushcclosure(lua_State *L, lua_CFunction fn, int n)
typedef void (*LuaPushCClosure_t)(lua_State* L, void* fn, int n);
static LuaPushCClosure_t g_OriginalPushCClosure = nullptr;
static int g_PushCClosureCount = 0;

static void Hooked_lua_pushcclosure(lua_State* L, void* fn, int n) {
    g_PushCClosureCount++;
    
    // Log first several calls
    if (g_PushCClosureCount <= 20) {
        Log("[LuaBridge] lua_pushcclosure #%d: L=0x%p, fn=0x%p, n=%d", 
            g_PushCClosureCount, L, fn, n);
    }
    
    // Capture lua_State on first call
    if (L && !g_LuaState) {
        Log("[LuaBridge] Captured lua_State from lua_pushcclosure: 0x%p", L);
        g_LuaState = L;
    }
    
    // Call original - must complete before we do anything
    g_OriginalPushCClosure(L, fn, n);
    
    // After 10+ closures have been registered (Lua is initialized),
    // register our functions. We do this after the original call completes.
    // The key is that WE ARE ON THE GAME'S MAIN THREAD here.
    if (g_LuaState && !g_COAExtenderRegistered && g_PushCClosureCount == 10) {
        Log("[LuaBridge] Registering COA_Extender after %d closures...", g_PushCClosureCount);
        
        // Check stack state
        int top = p_lua_gettop ? p_lua_gettop(g_LuaState) : -1;
        Log("[LuaBridge] Stack top before registration: %d", top);
        
        RegisterFunctions(g_LuaState);
        g_COAExtenderRegistered = true;
        
        int newTop = p_lua_gettop ? p_lua_gettop(g_LuaState) : -1;
        Log("[LuaBridge] Stack top after registration: %d", newTop);
        Log("[LuaBridge] COA_Extender registered successfully!");
    }
}

// === APPROACH 1: Hook lua_pcall - backup if pushcclosure doesn't work ===
typedef int (*LuaPcall_t)(lua_State* L, int nargs, int nresults, int errfunc);
static LuaPcall_t g_OriginalPcall = nullptr;
static int g_PcallCount = 0;

static int Hooked_lua_pcall(lua_State* L, int nargs, int nresults, int errfunc) {
    g_PcallCount++;
    
    // Only log first few calls to avoid spam
    if (g_PcallCount <= 5) {
        Log("[LuaBridge] lua_pcall #%d called! lua_State=0x%p, nargs=%d, nresults=%d", 
            g_PcallCount, L, nargs, nresults);
    }
    
    // Capture lua_State on first call
    if (L && !g_LuaState) {
        Log("[LuaBridge] Captured lua_State from lua_pcall: 0x%p", L);
        g_LuaState = L;
    }
    
    // Call original pcall
    int result = g_OriginalPcall(L, nargs, nresults, errfunc);
    
    // NOTE: This hook is currently disabled, registration happens via lua_pushcclosure
    
    return result;
}

// === APPROACH 2: Hook lua_newstate to capture lua_State* when created ===
typedef lua_State* (*LuaNewstate_t)(void* allocFunc, void* userData);
static LuaNewstate_t g_OriginalNewstate = nullptr;

static lua_State* Hooked_lua_newstate(void* allocFunc, void* userData) {
    Log("[LuaBridge] lua_newstate called! allocFunc=0x%p, userData=0x%p", allocFunc, userData);
    
    lua_State* L = g_OriginalNewstate(allocFunc, userData);
    
    Log("[LuaBridge] lua_newstate returned lua_State* = 0x%p", L);
    
    if (L) {
        g_LuaState = L;
        Log("[LuaBridge] Captured lua_State from lua_newstate!");
    }
    
    return L;
}

// === APPROACH 2: Hook luaL_openlibs to register after libs are loaded ===
typedef void (*LuaL_openlibs_t)(lua_State* L);
static LuaL_openlibs_t g_OriginalOpenlibs = nullptr;

static void Hooked_luaL_openlibs(lua_State* L) {
    Log("[LuaBridge] luaL_openlibs called with lua_State* = 0x%p", L);
    
    // Call original first to set up standard libraries
    g_OriginalOpenlibs(L);
    
    Log("[LuaBridge] Standard Lua libraries loaded");
    
    // Just capture the state, don't register directly
    if (L && !g_LuaState) {
        g_LuaState = L;
        Log("[LuaBridge] Captured lua_State from luaL_openlibs");
    }
}

// === APPROACH 3: Read lua_State* from global variable ===
static lua_State* TryGetLuaStateFromGlobal() {
    // The game stores lua_State* at global address 0x141139B48
    uintptr_t globalAddr = g_GameBase + LUA_STATE_GLOBAL_OFFSET;
    
    // Log the address we're checking (only first time)
    static bool firstCheck = true;
    if (firstCheck) {
        Log("[LuaBridge] Checking for lua_State at global 0x%llX", globalAddr);
        firstCheck = false;
    }
    
    // This is a pointer to a pointer - dereference carefully
    lua_State** ppState = (lua_State**)globalAddr;
    
    // Check if the memory is readable
    if (IsBadReadPtr(ppState, sizeof(lua_State*))) {
        return nullptr;
    }
    
    lua_State* L = *ppState;
    
    // Log what we found (for debugging)
    static lua_State* lastChecked = (lua_State*)1; // Use 1 to trigger first log
    if (L != lastChecked) {
        Log("[LuaBridge] Global value changed: 0x%p", L);
        lastChecked = L;
    }
    
    if (L && !IsBadReadPtr(L, sizeof(void*))) {
        return L;
    }
    
    return nullptr;
}

// Periodic check for lua_State from global (called from game loop hook if needed)
void CheckForLuaState() {
    if (g_LuaState || g_COAExtenderRegistered) return;
    
    lua_State* L = TryGetLuaStateFromGlobal();
    if (L) {
        Log("[LuaBridge] Found lua_State from global: 0x%p", L);
        g_LuaState = L;
        RegisterFunctions(L);
        g_COAExtenderRegistered = true;
        Log("[LuaBridge] COA_Extender registered from global!");
    }
}

// === APPROACH 4: Background thread that periodically checks for Lua state ===
static HANDLE g_CheckThread = nullptr;
static bool g_CheckThreadRunning = false;

static DWORD WINAPI LuaStateCheckThread(LPVOID param) {
    Log("[LuaBridge] Background Lua state checker started");
    
    // Multiple candidate global addresses from AnalyzeLuaInitCaller.java
    const uintptr_t candidates[] = {
        0x01139B48,  // lua_State candidate 1 (used as RCX)
        0x01139B50,  // lua_State candidate 2 (used as RDX)  
        0x01137060,  // lua_State candidate 3 (frequently used)
    };
    const int numCandidates = sizeof(candidates) / sizeof(candidates[0]);
    
    int checkCount = 0;
    const int MAX_CHECKS = 120;  // Check for up to 120 seconds
    
    while (g_CheckThreadRunning && !g_COAExtenderRegistered && checkCount < MAX_CHECKS) {
        Sleep(1000);  // Check every second
        checkCount++;
        
        if (g_COAExtenderRegistered) break;
        
        // Check all candidate addresses
        for (int i = 0; i < numCandidates; i++) {
            uintptr_t globalAddr = g_GameBase + candidates[i];
            
            if (IsBadReadPtr((void*)globalAddr, sizeof(void*))) continue;
            
            void* ptrValue = *(void**)globalAddr;
            
            // Log on first check or if value changed
            static void* lastValues[3] = {nullptr, nullptr, nullptr};
            if (checkCount == 1 || ptrValue != lastValues[i]) {
                Log("[LuaBridge] [Thread] Global[%d] at 0x%llX = 0x%p", 
                    i, globalAddr, ptrValue);
                lastValues[i] = ptrValue;
            }
            
            // Check if this looks like a valid pointer
            if (ptrValue && !IsBadReadPtr(ptrValue, 64)) {
                // Try to validate it's a lua_State by checking structure
                // lua_State typically has specific patterns at known offsets
                lua_State* L = (lua_State*)ptrValue;
                
                // If we haven't registered yet and this looks valid, try it
                if (!g_COAExtenderRegistered) {
                    Log("[LuaBridge] [Thread] Testing candidate lua_State at 0x%p from global[%d]", L, i);
                    
                    std::lock_guard<std::mutex> lock(g_LuaMutex);
                    if (!g_COAExtenderRegistered) {
                        g_LuaState = L;
                        
                        // Try to call a simple Lua function to validate
                        // lua_gettop should return a small non-negative integer
                        if (p_lua_gettop) {
                            int top = p_lua_gettop(L);
                            Log("[LuaBridge] [Thread] lua_gettop returned %d", top);
                            if (top >= 0 && top < 1000) {
                                Log("[LuaBridge] [Thread] Valid lua_State confirmed!");
                                // NOTE: Cannot register from background thread (not thread-safe)
                                // Just log that we found a valid state
                                Log("[LuaBridge] [Thread] lua_State captured, will register via hook");
                                break;
                            } else {
                                Log("[LuaBridge] [Thread] Invalid result, not a valid lua_State");
                                g_LuaState = nullptr;
                            }
                        }
                    }
                }
            }
        }
        
        if (g_COAExtenderRegistered) break;
        
        if (checkCount % 10 == 0) {
            Log("[LuaBridge] [Thread] Still waiting for Lua state... (%d seconds)", checkCount);
        }
    }
    
    if (!g_COAExtenderRegistered) {
        Log("[LuaBridge] [Thread] Gave up waiting for Lua state after %d seconds", checkCount);
    }
    
    Log("[LuaBridge] Background checker thread exiting");
    return 0;
}

static void StartLuaStateChecker() {
    g_CheckThreadRunning = true;
    g_CheckThread = CreateThread(nullptr, 0, LuaStateCheckThread, nullptr, 0, nullptr);
}

static void StopLuaStateChecker() {
    g_CheckThreadRunning = false;
    if (g_CheckThread) {
        WaitForSingleObject(g_CheckThread, 2000);
        CloseHandle(g_CheckThread);
        g_CheckThread = nullptr;
    }
}

// Backup hook: lua.start 
static const uintptr_t LUA_START_RVA = LUA_START_HANDLER_OFFSET;
typedef void* (*LuaStart_t)(void* param1, void* param2);
static LuaStart_t g_OriginalLuaStart = nullptr;

static void* Hooked_LuaStart(void* param1, void* param2) {
    Log("[LuaBridge] lua.start handler called!");
    Log("[LuaBridge] param1=0x%p, param2=0x%p", param1, param2);
    
    void* result = g_OriginalLuaStart(param1, param2);
    
    Log("[LuaBridge] lua.start returned: 0x%p", result);
    
    // After lua.start, try to get state from global
    if (!g_COAExtenderRegistered) {
        CheckForLuaState();
    }
    
    return result;
}

// Install hooks
static bool InstallLuaHooks() {
    uintptr_t base = g_GameBase;
    bool success = false;
    MH_STATUS status;
    
    // PRIMARY: Hook lua_pushcclosure - called when game registers C functions in Lua
    // This has a well-defined signature: void lua_pushcclosure(lua_State *L, lua_CFunction fn, int n)
    void* pushcclosure_target = (void*)(base + LUA_PUSHCCLOSURE_OFFSET);
    Log("[LuaBridge] Installing hook at lua_pushcclosure (0x%p)", pushcclosure_target);
    
    status = MH_CreateHook(pushcclosure_target, (void*)Hooked_lua_pushcclosure, (void**)&g_OriginalPushCClosure);
    if (status != MH_OK) {
        Log("[LuaBridge] Failed to create lua_pushcclosure hook: %d", status);
    } else {
        status = MH_EnableHook(pushcclosure_target);
        if (status != MH_OK) {
            Log("[LuaBridge] Failed to enable lua_pushcclosure hook: %d", status);
        } else {
            Log("[LuaBridge] lua_pushcclosure hook installed successfully");
            success = true;
        }
    }
    
    Log("[LuaBridge] Hook installation complete (pushcclosure only)");
    
    // DISABLED: These hooks caused crashes or didn't fire
    #if 0
    // lua_pcall - never fired during testing
    void* pcall_target = (void*)(base + LUA_PCALL_OFFSET);
    Log("[LuaBridge] Installing hook at lua_pcall (0x%p)", pcall_target);
    
    status = MH_CreateHook(pcall_target, (void*)Hooked_lua_pcall, (void**)&g_OriginalPcall);
    if (status != MH_OK) {
        Log("[LuaBridge] Failed to create lua_pcall hook: %d", status);
    } else {
        status = MH_EnableHook(pcall_target);
        if (status != MH_OK) {
            Log("[LuaBridge] Failed to enable lua_pcall hook: %d", status);
        } else {
            Log("[LuaBridge] lua_pcall hook installed successfully");
            success = true;
        }
    }
    #endif
    
    // DISABLED: These hooks may interfere with game initialization
    #if 0
    // Secondary hook: lua_newstate (captures lua_State* when created)
    void* newstate_target = (void*)(base + LUA_NEWSTATE_OFFSET);
    Log("[LuaBridge] Installing hook at lua_newstate (0x%p)", newstate_target);
    
    status = MH_CreateHook(newstate_target, (void*)Hooked_lua_newstate, (void**)&g_OriginalNewstate);
    if (status != MH_OK) {
        Log("[LuaBridge] Failed to create lua_newstate hook: %d", status);
    } else {
        status = MH_EnableHook(newstate_target);
        if (status != MH_OK) {
            Log("[LuaBridge] Failed to enable lua_newstate hook: %d", status);
        } else {
            Log("[LuaBridge] lua_newstate hook installed successfully");
            success = true;
        }
    }
    
    // Tertiary hook: luaL_openlibs (register functions after libs loaded)
    void* openlibs_target = (void*)(base + LUAL_OPENLIBS_OFFSET);
    Log("[LuaBridge] Installing hook at luaL_openlibs (0x%p)", openlibs_target);
    
    status = MH_CreateHook(openlibs_target, (void*)Hooked_luaL_openlibs, (void**)&g_OriginalOpenlibs);
    if (status != MH_OK) {
        Log("[LuaBridge] Failed to create luaL_openlibs hook: %d", status);
    } else {
        status = MH_EnableHook(openlibs_target);
        if (status != MH_OK) {
            Log("[LuaBridge] Failed to enable luaL_openlibs hook: %d", status);
        } else {
            Log("[LuaBridge] luaL_openlibs hook installed successfully");
            success = true;
        }
    }
    
    // lua.start hook
    void* luastart_target = (void*)COA_RVA(LUA_START_RVA);
    Log("[LuaBridge] Installing hook at lua.start (0x%p)", luastart_target);
    
    status = MH_CreateHook(luastart_target, (void*)Hooked_LuaStart, (void**)&g_OriginalLuaStart);
    if (status == MH_OK) {
        status = MH_EnableHook(luastart_target);
        if (status == MH_OK) {
            Log("[LuaBridge] lua.start hook installed successfully");
            success = true;
        }
    }
    
    // Also try to get state from global immediately (in case Lua already initialized)
    Log("[LuaBridge] Checking global variable for existing lua_State...");
    CheckForLuaState();;
    
    // Start background thread to periodically check for Lua state
    if (!g_COAExtenderRegistered) {
        Log("[LuaBridge] Starting background Lua state checker thread...");
        StartLuaStateChecker();
    }
    #endif
    
    Log("[LuaBridge] Hook installation complete (minimal mode - pcall only)");
    return success;
}

//=============================================================================
// PUBLIC API
//=============================================================================

void RegisterFunctions(lua_State* L) {
    if (!L) {
        Log("[LuaBridge] Cannot register - lua_State is NULL");
        return;
    }
    
    std::lock_guard<std::mutex> lock(g_LuaMutex);
    
    // Check if we have the required Lua functions
    if (!p_lua_createtable || !p_lua_setfield || !p_lua_setglobal || !p_lua_pushcclosure) {
        Log("[LuaBridge] Cannot register - Lua functions not resolved");
        Log("[LuaBridge] p_lua_createtable=%p, p_lua_setfield=%p, p_lua_setglobal=%p, p_lua_pushcclosure=%p",
            p_lua_createtable, p_lua_setfield, p_lua_setglobal, p_lua_pushcclosure);
        return;
    }
    
    Log("[LuaBridge] Registering COA_Extender table...");
    Log("[LuaBridge] lua_State* = 0x%p", L);
    Log("[LuaBridge] p_lua_createtable = 0x%p", p_lua_createtable);
    
    // First, verify the lua_State is valid by calling lua_gettop
    if (p_lua_gettop) {
        int top = p_lua_gettop(L);
        Log("[LuaBridge] Pre-check: lua_gettop returned %d", top);
        
        // If top is a crazy value, the state is invalid
        if (top < 0 || top > 10000) {
            Log("[LuaBridge] ERROR: lua_State appears invalid (stack top = %d)", top);
            return;
        }
    }
    
    // Save stack position to restore later
    int savedTop = p_lua_gettop ? p_lua_gettop(L) : 0;
    
    Log("[LuaBridge] About to call lua_createtable...");
    
    // Create the COA_Extender table
    // lua_createtable(L, narr, nrec) - narr=0, nrec=12 for our functions
    p_lua_createtable(L, 0, 12);
    
    Log("[LuaBridge] lua_createtable succeeded, adding functions...");
    
    // Add functions to the table
    #define REGISTER_FUNC(name, func) \
        p_lua_pushcclosure(L, (lua_CFunction)func, 0); \
        p_lua_setfield(L, -2, name)
    
    REGISTER_FUNC("GetVersion", L_GetVersion);
    REGISTER_FUNC("Log", L_Log);
    REGISTER_FUNC("IsActive", L_IsActive);
    REGISTER_FUNC("GetGameBase", L_GetGameBase);
    REGISTER_FUNC("SetDamageMultiplier", L_SetDamageMultiplier);
    REGISTER_FUNC("GetDamageMultiplier", L_GetDamageMultiplier);
    REGISTER_FUNC("SetGodMode", L_SetGodMode);
    REGISTER_FUNC("IsGodMode", L_IsGodMode);
    REGISTER_FUNC("SetUnlimitedAmmo", L_SetUnlimitedAmmo);
    REGISTER_FUNC("IsUnlimitedAmmo", L_IsUnlimitedAmmo);
    REGISTER_FUNC("GetLoadedMods", L_GetLoadedMods);
    REGISTER_FUNC("ExecuteHook", L_ExecuteHook);
    
    #undef REGISTER_FUNC
    
    Log("[LuaBridge] Functions added, setting global...");
    
    // Set as global COA_Extender
    p_lua_setglobal(L, "COA_Extender");
    
    g_LuaState = L;
    Log("[LuaBridge] COA_Extender table registered in Lua");
}

bool Initialize() {
    if (g_Initialized) return true;
    
    Log("[LuaBridge] Initializing Lua bridge...");
    
    // Resolve Lua function addresses from the game
    ResolveLuaFunctions();
    
    // Install hooks to capture lua_State*
    if (InstallLuaHooks()) {
        Log("[LuaBridge] Hooks installed - will register COA_Extender when Lua initializes");
    } else {
        Log("[LuaBridge] Warning: Could not install Lua hooks");
    }
    
    g_Initialized = true;
    Log("[LuaBridge] Lua bridge initialized");
    return true;
}

void Shutdown() {
    // Stop background checker first (outside lock to avoid deadlock)
    StopLuaStateChecker();
    
    std::lock_guard<std::mutex> lock(g_LuaMutex);
    
    uintptr_t base = g_GameBase;
    
    // Remove lua_newstate hook
    if (g_OriginalNewstate) {
        void* target = (void*)(base + LUA_NEWSTATE_OFFSET);
        MH_DisableHook(target);
        MH_RemoveHook(target);
        g_OriginalNewstate = nullptr;
    }
    
    // Remove luaL_openlibs hook
    if (g_OriginalOpenlibs) {
        void* target = (void*)(base + LUAL_OPENLIBS_OFFSET);
        MH_DisableHook(target);
        MH_RemoveHook(target);
        g_OriginalOpenlibs = nullptr;
    }
    
    // Remove lua.start hook
    if (g_OriginalLuaStart) {
        void* target = (void*)COA_RVA(LUA_START_RVA);
        MH_DisableHook(target);
        MH_RemoveHook(target);
        g_OriginalLuaStart = nullptr;
    }
    
    // Remove lua_pcall hook
    if (g_OriginalPcall) {
        void* target = (void*)(base + LUA_PCALL_OFFSET);
        MH_DisableHook(target);
        MH_RemoveHook(target);
        g_OriginalPcall = nullptr;
    }
    
    // Remove lua_pushcclosure hook
    if (g_OriginalPushCClosure) {
        void* target = (void*)(base + LUA_PUSHCCLOSURE_OFFSET);
        MH_DisableHook(target);
        MH_RemoveHook(target);
        g_OriginalPushCClosure = nullptr;
    }
    
    g_LuaState = nullptr;
    g_Initialized = false;
    g_COAExtenderRegistered = false;
    g_LuaLogMessages.clear();
    Log("[LuaBridge] Shutdown complete");
}

bool IsActive() {
    return g_Initialized && g_LuaState != nullptr;
}

lua_State* GetState() {
    return g_LuaState;
}

// Accessor for damage multiplier (used by hooks)
float GetDamageMultiplier() {
    return g_DamageMultiplier;
}

bool IsGodModeEnabled() {
    return g_GodMode;
}

bool IsUnlimitedAmmoEnabled() {
    return g_UnlimitedAmmo;
}

} // namespace Lua
} // namespace COA
