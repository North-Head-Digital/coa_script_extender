/**
 * COA Script Extender - Plugin API
 * 
 * This header defines the public API that plugin DLLs use to extend the
 * script extender. Plugins can:
 * 
 *   1. Register custom Lua functions that appear in the COA_Extender table
 *   2. Subscribe to game events (unit spawned, damage dealt, etc.)
 *   3. Access the Lua state directly for advanced operations
 * 
 * USAGE IN YOUR MOD:
 * 
 *   #include "coa_plugin_api.h"
 *   
 *   // Register a Lua function
 *   int MyLuaFunc(lua_State* L) {
 *       // Your code here
 *       return 0;
 *   }
 *   
 *   extern "C" __declspec(dllexport) bool ModInit() {
 *       COA_RegisterLuaFunction("MyFunction", MyLuaFunc);
 *       COA_SubscribeEvent(COA_EVENT_UNIT_SPAWNED, OnUnitSpawned);
 *       return true;
 *   }
 * 
 * YOUR FUNCTION WILL BE CALLABLE FROM LUA:
 * 
 *   COA_Extender.MyFunction(arg1, arg2)
 *   -- or --
 *   COA_Plugins.YourMod.MyFunction(arg1, arg2)  (if using namespaced registration)
 */

#pragma once

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

//=============================================================================
// LUA TYPES (Compatible with Lua 5.2)
//=============================================================================

typedef struct lua_State lua_State;
typedef double lua_Number;
typedef ptrdiff_t lua_Integer;
typedef int (*lua_CFunction)(lua_State* L);

//=============================================================================
// LUA STACK OPERATIONS (Helpers for plugin authors)
//=============================================================================

/**
 * These are pointers to the game's Lua functions, resolved at runtime.
 * Use them to interact with Lua from your plugin.
 */

// Stack manipulation
typedef int     (*COA_lua_gettop_t)(lua_State* L);
typedef void    (*COA_lua_settop_t)(lua_State* L, int idx);
typedef void    (*COA_lua_pushvalue_t)(lua_State* L, int idx);
typedef void    (*COA_lua_remove_t)(lua_State* L, int idx);
typedef int     (*COA_lua_type_t)(lua_State* L, int idx);

// Push values
typedef void    (*COA_lua_pushnil_t)(lua_State* L);
typedef void    (*COA_lua_pushnumber_t)(lua_State* L, lua_Number n);
typedef void    (*COA_lua_pushinteger_t)(lua_State* L, lua_Integer n);
typedef void    (*COA_lua_pushstring_t)(lua_State* L, const char* s);
typedef void    (*COA_lua_pushboolean_t)(lua_State* L, int b);
typedef void    (*COA_lua_pushcclosure_t)(lua_State* L, lua_CFunction fn, int n);
typedef void    (*COA_lua_pushlightuserdata_t)(lua_State* L, void* p);

// Get values
typedef lua_Number  (*COA_lua_tonumber_t)(lua_State* L, int idx);
typedef lua_Integer (*COA_lua_tointeger_t)(lua_State* L, int idx);
typedef const char* (*COA_lua_tostring_t)(lua_State* L, int idx);
typedef int         (*COA_lua_toboolean_t)(lua_State* L, int idx);
typedef void*       (*COA_lua_touserdata_t)(lua_State* L, int idx);

// Table operations
typedef void    (*COA_lua_createtable_t)(lua_State* L, int narr, int nrec);
typedef void    (*COA_lua_settable_t)(lua_State* L, int idx);
typedef void    (*COA_lua_gettable_t)(lua_State* L, int idx);
typedef void    (*COA_lua_setfield_t)(lua_State* L, int idx, const char* k);
typedef void    (*COA_lua_getfield_t)(lua_State* L, int idx, const char* k);
typedef void    (*COA_lua_rawgeti_t)(lua_State* L, int idx, int n);
typedef void    (*COA_lua_rawseti_t)(lua_State* L, int idx, int n);

// Misc
typedef int     (*COA_lua_pcall_t)(lua_State* L, int nargs, int nresults, int msgh);
typedef void    (*COA_lua_error_t)(lua_State* L);
typedef int     (*COA_luaL_error_t)(lua_State* L, const char* fmt, ...);

/**
 * Lua API function table - filled in by the extender at plugin load time.
 * Check for NULL before using.
 */
typedef struct {
    // Stack
    COA_lua_gettop_t            lua_gettop;
    COA_lua_settop_t            lua_settop;
    COA_lua_pushvalue_t         lua_pushvalue;
    COA_lua_remove_t            lua_remove;
    COA_lua_type_t              lua_type;
    
    // Push
    COA_lua_pushnil_t           lua_pushnil;
    COA_lua_pushnumber_t        lua_pushnumber;
    COA_lua_pushinteger_t       lua_pushinteger;
    COA_lua_pushstring_t        lua_pushstring;
    COA_lua_pushboolean_t       lua_pushboolean;
    COA_lua_pushcclosure_t      lua_pushcclosure;
    COA_lua_pushlightuserdata_t lua_pushlightuserdata;
    
    // Get
    COA_lua_tonumber_t          lua_tonumber;
    COA_lua_tointeger_t         lua_tointeger;
    COA_lua_tostring_t          lua_tostring;
    COA_lua_toboolean_t         lua_toboolean;
    COA_lua_touserdata_t        lua_touserdata;
    
    // Table
    COA_lua_createtable_t       lua_createtable;
    COA_lua_settable_t          lua_settable;
    COA_lua_gettable_t          lua_gettable;
    COA_lua_setfield_t          lua_setfield;
    COA_lua_getfield_t          lua_getfield;
    COA_lua_rawgeti_t           lua_rawgeti;
    COA_lua_rawseti_t           lua_rawseti;
    
    // Misc
    COA_lua_pcall_t             lua_pcall;
    COA_lua_error_t             lua_error;
    COA_luaL_error_t            luaL_error;
    
} COA_LuaAPI;

/**
 * Get the Lua API function table.
 * Returns NULL if the Lua bridge is not yet initialized.
 */
typedef const COA_LuaAPI* (*COA_GetLuaAPI_t)(void);

//=============================================================================
// PLUGIN REGISTRATION
//=============================================================================

/**
 * Register a Lua function that will be exposed in COA_Extender.
 * 
 * @param name      The function name (e.g., "MyFunction")
 * @param func      The C function to call
 * @return          true on success, false if registration failed
 * 
 * The function will be accessible as: COA_Extender.MyFunction(...)
 * 
 * Your function receives arguments on the Lua stack and should return
 * the number of return values pushed onto the stack.
 */
typedef bool (*COA_RegisterLuaFunction_t)(const char* name, lua_CFunction func);

/**
 * Register a Lua function under a custom namespace.
 * 
 * @param ns        Namespace name (e.g., "MyMod")
 * @param name      The function name (e.g., "DoSomething")
 * @param func      The C function to call
 * @return          true on success
 * 
 * Creates: COA_Plugins.MyMod.DoSomething(...)
 */
typedef bool (*COA_RegisterNamespacedFunction_t)(const char* ns, const char* name, lua_CFunction func);

/**
 * Get the current Lua state.
 * Returns NULL if not in a Lua context or the bridge isn't initialized.
 */
typedef lua_State* (*COA_GetLuaState_t)(void);

/**
 * Get the game's base address.
 */
typedef uintptr_t (*COA_GetGameBase_t)(void);

//=============================================================================
// EVENT SYSTEM
//=============================================================================

/**
 * Event types that plugins can subscribe to.
 */
typedef enum {
    COA_EVENT_NONE = 0,
    
    // Game lifecycle
    COA_EVENT_GAME_STARTED,         // Game started (map loaded)
    COA_EVENT_GAME_ENDED,           // Game ended
    COA_EVENT_TICK,                 // Game tick (called every frame)
    
    // Unit events
    COA_EVENT_UNIT_SPAWNED,         // Unit created
    COA_EVENT_UNIT_KILLED,          // Unit killed
    COA_EVENT_UNIT_DAMAGED,         // Unit took damage
    COA_EVENT_UNIT_HEALED,          // Unit healed
    
    // Combat events
    COA_EVENT_DAMAGE_DEALT,         // Damage was dealt
    COA_EVENT_WEAPON_FIRED,         // Weapon fired
    COA_EVENT_EXPLOSION,            // Explosion occurred
    
    // Vehicle events
    COA_EVENT_VEHICLE_SPAWNED,      // Vehicle created
    COA_EVENT_VEHICLE_DESTROYED,    // Vehicle destroyed
    COA_EVENT_VEHICLE_ENTERED,      // Unit entered vehicle
    COA_EVENT_VEHICLE_EXITED,       // Unit exited vehicle
    
    // AI events
    COA_EVENT_AI_DECISION,          // AI made a decision
    COA_EVENT_AI_COMMAND,           // AI issued a command
    
    // Lua events
    COA_EVENT_LUA_LOADED,           // Lua state became available
    COA_EVENT_LUA_SCRIPT_RUN,       // A Lua script was executed
    
    COA_EVENT_MAX
} COA_EventType;

/**
 * Event data structure passed to event callbacks.
 * Check the 'type' field to know which union member is valid.
 */
typedef struct {
    COA_EventType type;
    
    union {
        // Generic event data
        struct {
            void* ptr1;
            void* ptr2;
            float value1;
            float value2;
        } generic;
        
        // Unit events
        struct {
            void* unit;         // Pointer to unit
            float health;       // Current health
            float maxHealth;    // Max health
        } unit;
        
        // Damage events
        struct {
            void* source;       // Source unit/weapon
            void* target;       // Target unit
            float damage;       // Damage amount
            int damageType;     // Type of damage
        } damage;
        
        // Vehicle events
        struct {
            void* vehicle;      // Pointer to vehicle
            void* unit;         // Related unit (for enter/exit)
        } vehicle;
        
        // Tick event
        struct {
            float deltaTime;    // Time since last tick
            double gameTime;    // Total game time
        } tick;
        
        // Lua events
        struct {
            lua_State* state;   // Lua state
            const char* script; // Script name (if applicable)
        } lua;
    };
    
} COA_EventData;

/**
 * Event callback function type.
 * Return true to allow the event to continue, false to cancel (if cancellable).
 */
typedef bool (*COA_EventCallback)(const COA_EventData* data);

/**
 * Subscribe to an event.
 * 
 * @param type      The event type to subscribe to
 * @param callback  Function to call when event occurs
 * @return          Subscription ID (0 if failed)
 */
typedef uint32_t (*COA_SubscribeEvent_t)(COA_EventType type, COA_EventCallback callback);

/**
 * Unsubscribe from an event.
 * 
 * @param subscriptionId    ID returned from COA_SubscribeEvent
 */
typedef void (*COA_UnsubscribeEvent_t)(uint32_t subscriptionId);

//=============================================================================
// PLUGIN API TABLE
//=============================================================================

/**
 * The complete Plugin API table.
 * This is provided to your ModInit() function.
 */
typedef struct {
    uint32_t version;               // API version (currently 1)
    uint32_t size;                  // Size of this struct (for compatibility)
    
    // Core
    COA_GetGameBase_t       GetGameBase;
    COA_GetLuaState_t       GetLuaState;
    COA_GetLuaAPI_t         GetLuaAPI;
    
    // Lua function registration
    COA_RegisterLuaFunction_t           RegisterLuaFunction;
    COA_RegisterNamespacedFunction_t    RegisterNamespacedFunction;
    
    // Events
    COA_SubscribeEvent_t    SubscribeEvent;
    COA_UnsubscribeEvent_t  UnsubscribeEvent;
    
} COA_PluginAPI;

//=============================================================================
// PLUGIN EXPORTS (What your mod must export)
//=============================================================================

/**
 * Your mod DLL must export these functions:
 * 
 *   bool ModInit(const COA_PluginAPI* api);
 *   void ModShutdown(void);
 *   void ModTick(float deltaTime);
 *   const char* ModGetName(void);
 *   const char* ModGetVersion(void);
 *   const char* ModGetAuthor(void);
 * 
 * ModInit receives the Plugin API table. Store it for later use:
 * 
 *   static const COA_PluginAPI* g_API = nullptr;
 *   
 *   extern "C" __declspec(dllexport) bool ModInit(const COA_PluginAPI* api) {
 *       g_API = api;
 *       g_API->RegisterLuaFunction("MyFunc", MyLuaFunction);
 *       return true;
 *   }
 */

// Function pointer types for loading plugin exports
typedef bool (*ModInit_t)(const COA_PluginAPI* api);
typedef void (*ModShutdown_t)(void);
typedef void (*ModTick_t)(float deltaTime);
typedef const char* (*ModGetName_t)(void);
typedef const char* (*ModGetVersion_t)(void);
typedef const char* (*ModGetAuthor_t)(void);

//=============================================================================
// CONVENIENCE MACROS
//=============================================================================

/**
 * Helper macros for plugin Lua function definitions.
 * 
 * Usage:
 *   COA_LUA_FUNCTION(MyFunction) {
 *       int arg1 = (int)lua->lua_tointeger(L, 1);
 *       lua->lua_pushinteger(L, arg1 * 2);
 *       return 1;
 *   }
 */
#define COA_LUA_FUNCTION(name) \
    static int LuaFunc_##name(lua_State* L)

#define COA_REGISTER_LUA_FUNCTION(api, name) \
    (api)->RegisterLuaFunction(#name, LuaFunc_##name)

/**
 * Lua type constants (matches Lua 5.2)
 */
#define COA_LUA_TNONE           (-1)
#define COA_LUA_TNIL            0
#define COA_LUA_TBOOLEAN        1
#define COA_LUA_TLIGHTUSERDATA  2
#define COA_LUA_TNUMBER         3
#define COA_LUA_TSTRING         4
#define COA_LUA_TTABLE          5
#define COA_LUA_TFUNCTION       6
#define COA_LUA_TUSERDATA       7
#define COA_LUA_TTHREAD         8

/**
 * Lua special indices
 */
#define COA_LUA_REGISTRYINDEX   (-1001000)
#define COA_LUA_RIDX_GLOBALS    2

#ifdef __cplusplus
}
#endif
