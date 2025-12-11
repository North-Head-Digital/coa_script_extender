/**
 * COA Script Extender - Plugin API Implementation
 * 
 * This implements the Plugin API that mods use to extend the extender.
 */

#include "coa_plugin_api.h"
#include "coa_lua_bridge.h"
#include <windows.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <mutex>
#include <cstdio>

//=============================================================================
// LOGGING
//=============================================================================

static FILE* g_PluginLog = nullptr;

static void PluginLog(const char* fmt, ...) {
    if (!g_PluginLog) return;
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_PluginLog, "[%02d:%02d:%02d.%03d] [PluginAPI] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    
    va_list args;
    va_start(args, fmt);
    vfprintf(g_PluginLog, fmt, args);
    va_end(args);
    fprintf(g_PluginLog, "\n");
    fflush(g_PluginLog);
}

//=============================================================================
// GLOBALS
//=============================================================================

static uintptr_t g_GameBase = 0;
static bool g_Initialized = false;
static std::mutex g_Mutex;

// Registered Lua functions from plugins
struct PluginLuaFunc {
    std::string name;
    std::string ns;          // Namespace (empty for COA_Extender root)
    lua_CFunction func;
};

static std::vector<PluginLuaFunc> g_RegisteredFunctions;

// Event subscriptions
struct EventSubscription {
    uint32_t id;
    COA_EventType type;
    COA_EventCallback callback;
};

static std::vector<EventSubscription> g_EventSubscriptions;
static uint32_t g_NextSubscriptionId = 1;

// Loaded plugin modules
struct LoadedPlugin {
    HMODULE handle;
    std::string name;
    std::string version;
    std::string author;
    ModTick_t tick;
    ModShutdown_t shutdown;
};

static std::vector<LoadedPlugin> g_LoadedPlugins;

//=============================================================================
// LUA API TABLE
//=============================================================================

// Lua function offsets (from Ghidra analysis)
#define LUA_OFFSET_gettop           0x00D6FD10
#define LUA_OFFSET_settop           0x00D6B9B0
#define LUA_OFFSET_pushvalue        0x00D6AF40
#define LUA_OFFSET_remove           0x00D6B180
#define LUA_OFFSET_type             0x00D6BBC0
#define LUA_OFFSET_pushnil          0x00D6ADF0
#define LUA_OFFSET_pushnumber       0x00D6AEA0
#define LUA_OFFSET_pushinteger      0x00D6AE60
#define LUA_OFFSET_pushstring       0x00D6AED0
#define LUA_OFFSET_pushboolean      0x00D6ADA0
#define LUA_OFFSET_pushcclosure     0x00D6AB20
#define LUA_OFFSET_pushlightuserdata 0x00D6AE20
#define LUA_OFFSET_tonumber         0x00D6BAE0
#define LUA_OFFSET_tointeger        0x00D6BA50
#define LUA_OFFSET_tostring         0x00D6BB70
#define LUA_OFFSET_toboolean        0x00D6B9F0
#define LUA_OFFSET_touserdata       0x00D6BC20
#define LUA_OFFSET_createtable      0x00D69D40
#define LUA_OFFSET_settable         0x00D6B920
#define LUA_OFFSET_gettable         0x00D6A510
#define LUA_OFFSET_setfield         0x00D6B670
#define LUA_OFFSET_getfield         0x00D6A180
#define LUA_OFFSET_rawgeti          0x00D6B0B0
#define LUA_OFFSET_rawseti          0x00D6B130
#define LUA_OFFSET_pcall            0x00D6A900
#define LUA_OFFSET_error            0x00D69FD0
#define LUA_OFFSET_luaL_error       0x00D6E020

static COA_LuaAPI g_LuaAPI = {0};
static bool g_LuaAPIResolved = false;

static void ResolveLuaAPI() {
    if (g_LuaAPIResolved || g_GameBase == 0) return;
    
    g_LuaAPI.lua_gettop = (COA_lua_gettop_t)(g_GameBase + LUA_OFFSET_gettop);
    g_LuaAPI.lua_settop = (COA_lua_settop_t)(g_GameBase + LUA_OFFSET_settop);
    g_LuaAPI.lua_pushvalue = (COA_lua_pushvalue_t)(g_GameBase + LUA_OFFSET_pushvalue);
    g_LuaAPI.lua_remove = (COA_lua_remove_t)(g_GameBase + LUA_OFFSET_remove);
    g_LuaAPI.lua_type = (COA_lua_type_t)(g_GameBase + LUA_OFFSET_type);
    
    g_LuaAPI.lua_pushnil = (COA_lua_pushnil_t)(g_GameBase + LUA_OFFSET_pushnil);
    g_LuaAPI.lua_pushnumber = (COA_lua_pushnumber_t)(g_GameBase + LUA_OFFSET_pushnumber);
    g_LuaAPI.lua_pushinteger = (COA_lua_pushinteger_t)(g_GameBase + LUA_OFFSET_pushinteger);
    g_LuaAPI.lua_pushstring = (COA_lua_pushstring_t)(g_GameBase + LUA_OFFSET_pushstring);
    g_LuaAPI.lua_pushboolean = (COA_lua_pushboolean_t)(g_GameBase + LUA_OFFSET_pushboolean);
    g_LuaAPI.lua_pushcclosure = (COA_lua_pushcclosure_t)(g_GameBase + LUA_OFFSET_pushcclosure);
    g_LuaAPI.lua_pushlightuserdata = (COA_lua_pushlightuserdata_t)(g_GameBase + LUA_OFFSET_pushlightuserdata);
    
    g_LuaAPI.lua_tonumber = (COA_lua_tonumber_t)(g_GameBase + LUA_OFFSET_tonumber);
    g_LuaAPI.lua_tointeger = (COA_lua_tointeger_t)(g_GameBase + LUA_OFFSET_tointeger);
    g_LuaAPI.lua_tostring = (COA_lua_tostring_t)(g_GameBase + LUA_OFFSET_tostring);
    g_LuaAPI.lua_toboolean = (COA_lua_toboolean_t)(g_GameBase + LUA_OFFSET_toboolean);
    g_LuaAPI.lua_touserdata = (COA_lua_touserdata_t)(g_GameBase + LUA_OFFSET_touserdata);
    
    g_LuaAPI.lua_createtable = (COA_lua_createtable_t)(g_GameBase + LUA_OFFSET_createtable);
    g_LuaAPI.lua_settable = (COA_lua_settable_t)(g_GameBase + LUA_OFFSET_settable);
    g_LuaAPI.lua_gettable = (COA_lua_gettable_t)(g_GameBase + LUA_OFFSET_gettable);
    g_LuaAPI.lua_setfield = (COA_lua_setfield_t)(g_GameBase + LUA_OFFSET_setfield);
    g_LuaAPI.lua_getfield = (COA_lua_getfield_t)(g_GameBase + LUA_OFFSET_getfield);
    g_LuaAPI.lua_rawgeti = (COA_lua_rawgeti_t)(g_GameBase + LUA_OFFSET_rawgeti);
    g_LuaAPI.lua_rawseti = (COA_lua_rawseti_t)(g_GameBase + LUA_OFFSET_rawseti);
    
    g_LuaAPI.lua_pcall = (COA_lua_pcall_t)(g_GameBase + LUA_OFFSET_pcall);
    g_LuaAPI.lua_error = (COA_lua_error_t)(g_GameBase + LUA_OFFSET_error);
    g_LuaAPI.luaL_error = (COA_luaL_error_t)(g_GameBase + LUA_OFFSET_luaL_error);
    
    g_LuaAPIResolved = true;
    PluginLog("Lua API resolved");
}

//=============================================================================
// API IMPLEMENTATION
//=============================================================================

static const COA_LuaAPI* API_GetLuaAPI() {
    if (!g_LuaAPIResolved) {
        ResolveLuaAPI();
    }
    return g_LuaAPIResolved ? &g_LuaAPI : nullptr;
}

static lua_State* API_GetLuaState() {
    return COA::Lua::GetState();
}

static uintptr_t API_GetGameBase() {
    return g_GameBase;
}

static bool API_RegisterLuaFunction(const char* name, lua_CFunction func) {
    if (!name || !func) {
        PluginLog("RegisterLuaFunction: NULL name or func");
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_Mutex);
    
    PluginLuaFunc entry;
    entry.name = name;
    entry.ns = "";  // Root namespace (COA_Extender)
    entry.func = func;
    
    g_RegisteredFunctions.push_back(entry);
    PluginLog("Registered Lua function: %s", name);
    
    return true;
}

static bool API_RegisterNamespacedFunction(const char* ns, const char* name, lua_CFunction func) {
    if (!ns || !name || !func) {
        PluginLog("RegisterNamespacedFunction: NULL parameter");
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_Mutex);
    
    PluginLuaFunc entry;
    entry.name = name;
    entry.ns = ns;
    entry.func = func;
    
    g_RegisteredFunctions.push_back(entry);
    PluginLog("Registered namespaced Lua function: %s.%s", ns, name);
    
    return true;
}

static uint32_t API_SubscribeEvent(COA_EventType type, COA_EventCallback callback) {
    if (!callback || type <= COA_EVENT_NONE || type >= COA_EVENT_MAX) {
        PluginLog("SubscribeEvent: Invalid parameters");
        return 0;
    }
    
    std::lock_guard<std::mutex> lock(g_Mutex);
    
    EventSubscription sub;
    sub.id = g_NextSubscriptionId++;
    sub.type = type;
    sub.callback = callback;
    
    g_EventSubscriptions.push_back(sub);
    PluginLog("Subscribed to event %d with ID %u", (int)type, sub.id);
    
    return sub.id;
}

static void API_UnsubscribeEvent(uint32_t subscriptionId) {
    std::lock_guard<std::mutex> lock(g_Mutex);
    
    for (auto it = g_EventSubscriptions.begin(); it != g_EventSubscriptions.end(); ++it) {
        if (it->id == subscriptionId) {
            g_EventSubscriptions.erase(it);
            PluginLog("Unsubscribed event ID %u", subscriptionId);
            return;
        }
    }
}

//=============================================================================
// PLUGIN API TABLE
//=============================================================================

static COA_PluginAPI g_PluginAPI = {
    1,                              // version
    sizeof(COA_PluginAPI),          // size
    API_GetGameBase,
    API_GetLuaState,
    API_GetLuaAPI,
    API_RegisterLuaFunction,
    API_RegisterNamespacedFunction,
    API_SubscribeEvent,
    API_UnsubscribeEvent
};

//=============================================================================
// EVENT DISPATCH
//=============================================================================

namespace COA {
namespace PluginAPI {

bool DispatchEvent(const COA_EventData* data) {
    if (!data) return true;
    
    std::lock_guard<std::mutex> lock(g_Mutex);
    
    bool result = true;
    for (const auto& sub : g_EventSubscriptions) {
        if (sub.type == data->type) {
            if (!sub.callback(data)) {
                result = false;
            }
        }
    }
    return result;
}

void DispatchTick(float deltaTime, double gameTime) {
    COA_EventData data;
    memset(&data, 0, sizeof(data));
    data.type = COA_EVENT_TICK;
    data.tick.deltaTime = deltaTime;
    data.tick.gameTime = gameTime;
    DispatchEvent(&data);
}

void DispatchLuaLoaded(void* L_) {
    lua_State* L = (lua_State*)L_;
    COA_EventData data;
    memset(&data, 0, sizeof(data));
    data.type = COA_EVENT_LUA_LOADED;
    data.lua.state = L;
    data.lua.script = nullptr;
    DispatchEvent(&data);
}

} // namespace PluginAPI
} // namespace COA

//=============================================================================
// PLUGIN LOADING
//=============================================================================

namespace COA {
namespace PluginAPI {

static void LoadPlugin(const char* path) {
    PluginLog("Loading plugin: %s", path);
    
    HMODULE handle = LoadLibraryA(path);
    if (!handle) {
        PluginLog("Failed to load: %s (error %lu)", path, GetLastError());
        return;
    }
    
    ModInit_t init = (ModInit_t)GetProcAddress(handle, "ModInit");
    ModShutdown_t shutdown = (ModShutdown_t)GetProcAddress(handle, "ModShutdown");
    ModTick_t tick = (ModTick_t)GetProcAddress(handle, "ModTick");
    ModGetName_t getName = (ModGetName_t)GetProcAddress(handle, "ModGetName");
    ModGetVersion_t getVersion = (ModGetVersion_t)GetProcAddress(handle, "ModGetVersion");
    ModGetAuthor_t getAuthor = (ModGetAuthor_t)GetProcAddress(handle, "ModGetAuthor");
    
    if (!init) {
        PluginLog("Plugin missing ModInit export: %s", path);
        FreeLibrary(handle);
        return;
    }
    
    // Call ModInit with the API table
    if (!init(&g_PluginAPI)) {
        PluginLog("Plugin ModInit returned false: %s", path);
        FreeLibrary(handle);
        return;
    }
    
    LoadedPlugin plugin;
    plugin.handle = handle;
    plugin.name = getName ? getName() : "Unknown";
    plugin.version = getVersion ? getVersion() : "1.0.0";
    plugin.author = getAuthor ? getAuthor() : "Unknown";
    plugin.tick = tick;
    plugin.shutdown = shutdown;
    
    g_LoadedPlugins.push_back(plugin);
    
    PluginLog("Loaded plugin: %s v%s by %s", 
              plugin.name.c_str(), plugin.version.c_str(), plugin.author.c_str());
}

void LoadAllPlugins() {
    char modsPath[MAX_PATH];
    GetModuleFileNameA(nullptr, modsPath, MAX_PATH);
    char* slash = strrchr(modsPath, '\\');
    if (slash) {
        strcpy(slash + 1, "mods\\*.dll");
    } else {
        strcpy(modsPath, "mods\\*.dll");
    }
    
    PluginLog("Searching for plugins: %s", modsPath);
    
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(modsPath, &fd);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        PluginLog("No plugins found in mods folder");
        return;
    }
    
    // Get base path
    char basePath[MAX_PATH];
    GetModuleFileNameA(nullptr, basePath, MAX_PATH);
    slash = strrchr(basePath, '\\');
    if (slash) {
        strcpy(slash + 1, "mods\\");
    } else {
        strcpy(basePath, "mods\\");
    }
    
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        
        char fullPath[MAX_PATH];
        snprintf(fullPath, MAX_PATH, "%s%s", basePath, fd.cFileName);
        
        LoadPlugin(fullPath);
        
    } while (FindNextFileA(hFind, &fd));
    
    FindClose(hFind);
    
    PluginLog("Loaded %zu plugins", g_LoadedPlugins.size());
}

void UnloadAllPlugins() {
    PluginLog("Unloading %zu plugins", g_LoadedPlugins.size());
    
    for (auto& plugin : g_LoadedPlugins) {
        if (plugin.shutdown) {
            plugin.shutdown();
        }
        FreeLibrary(plugin.handle);
    }
    
    g_LoadedPlugins.clear();
    g_RegisteredFunctions.clear();
    g_EventSubscriptions.clear();
}

void TickAllPlugins(float deltaTime) {
    for (auto& plugin : g_LoadedPlugins) {
        if (plugin.tick) {
            plugin.tick(deltaTime);
        }
    }
    
    // Also dispatch tick event
    DispatchTick(deltaTime, 0.0);
}

//=============================================================================
// LUA REGISTRATION
//=============================================================================

void RegisterPluginFunctionsToLua(void* L_) {
    lua_State* L = (lua_State*)L_;
    if (!L) return;
    
    std::lock_guard<std::mutex> lock(g_Mutex);
    
    if (g_RegisteredFunctions.empty()) {
        PluginLog("No plugin functions to register");
        return;
    }
    
    PluginLog("Registering %zu plugin functions to Lua", g_RegisteredFunctions.size());
    
    // Get COA_Extender table
    // rawgeti(L, REGISTRYINDEX, 2) -> _G
    // getfield(L, -1, "COA_Extender") -> COA_Extender table
    
    g_LuaAPI.lua_rawgeti(L, -1001000, 2);  // _G
    g_LuaAPI.lua_getfield(L, -1, "COA_Extender");
    
    // Check if COA_Extender exists
    if (g_LuaAPI.lua_type(L, -1) != COA_LUA_TTABLE) {
        PluginLog("COA_Extender table not found, creating it");
        g_LuaAPI.lua_settop(L, -2);  // pop nil
        g_LuaAPI.lua_createtable(L, 0, 8);
        g_LuaAPI.lua_pushvalue(L, -1);  // duplicate
        g_LuaAPI.lua_setfield(L, -3, "COA_Extender");
    }
    
    // COA_Extender is now at top of stack
    
    // Create COA_Plugins table in _G for namespaced functions
    g_LuaAPI.lua_rawgeti(L, -1001000, 2);  // _G
    g_LuaAPI.lua_getfield(L, -1, "COA_Plugins");
    if (g_LuaAPI.lua_type(L, -1) != COA_LUA_TTABLE) {
        g_LuaAPI.lua_settop(L, -2);  // pop nil
        g_LuaAPI.lua_createtable(L, 0, 8);
        g_LuaAPI.lua_pushvalue(L, -1);
        g_LuaAPI.lua_setfield(L, -3, "COA_Plugins");
    }
    // Stack: COA_Extender, _G, COA_Plugins
    g_LuaAPI.lua_remove(L, -2);  // Remove _G
    // Stack: COA_Extender, COA_Plugins
    
    // Track namespaces we've created
    std::unordered_map<std::string, bool> createdNamespaces;
    
    for (const auto& func : g_RegisteredFunctions) {
        if (func.ns.empty()) {
            // Register directly in COA_Extender
            g_LuaAPI.lua_pushcclosure(L, func.func, 0);
            g_LuaAPI.lua_setfield(L, -3, func.name.c_str());  // COA_Extender is at -3
            PluginLog("Registered: COA_Extender.%s", func.name.c_str());
        } else {
            // Register in COA_Plugins.Namespace
            // Get or create the namespace table
            g_LuaAPI.lua_getfield(L, -1, func.ns.c_str());
            if (g_LuaAPI.lua_type(L, -1) != COA_LUA_TTABLE) {
                g_LuaAPI.lua_settop(L, -2);  // pop nil
                g_LuaAPI.lua_createtable(L, 0, 4);
                g_LuaAPI.lua_pushvalue(L, -1);
                g_LuaAPI.lua_setfield(L, -3, func.ns.c_str());
            }
            
            // Register function in namespace table
            g_LuaAPI.lua_pushcclosure(L, func.func, 0);
            g_LuaAPI.lua_setfield(L, -2, func.name.c_str());
            g_LuaAPI.lua_settop(L, -2);  // pop namespace table
            
            PluginLog("Registered: COA_Plugins.%s.%s", func.ns.c_str(), func.name.c_str());
        }
    }
    
    // Clean up stack
    g_LuaAPI.lua_settop(L, -3);  // pop COA_Extender and COA_Plugins
}

const std::vector<PluginLuaFunc>& GetRegisteredFunctions() {
    return g_RegisteredFunctions;
}

//=============================================================================
// INITIALIZATION
//=============================================================================

bool Initialize(uintptr_t gameBase) {
    if (g_Initialized) return true;
    
    g_GameBase = gameBase;
    
    // Open log file
    char logPath[MAX_PATH];
    GetModuleFileNameA(nullptr, logPath, MAX_PATH);
    char* slash = strrchr(logPath, '\\');
    if (slash) strcpy(slash + 1, "coa_plugin_api.log");
    
    g_PluginLog = fopen(logPath, "w");
    if (g_PluginLog) {
        PluginLog("=== COA Plugin API Initialized ===");
        PluginLog("Game base: 0x%llX", g_GameBase);
    }
    
    // Resolve Lua API
    ResolveLuaAPI();
    
    g_Initialized = true;
    
    // Load all plugins
    LoadAllPlugins();
    
    return true;
}

void Shutdown() {
    if (!g_Initialized) return;
    
    PluginLog("=== COA Plugin API Shutdown ===");
    
    UnloadAllPlugins();
    
    if (g_PluginLog) {
        fclose(g_PluginLog);
        g_PluginLog = nullptr;
    }
    
    g_Initialized = false;
}

bool IsInitialized() {
    return g_Initialized;
}

const COA_PluginAPI* GetAPI() {
    return &g_PluginAPI;
}

} // namespace PluginAPI
} // namespace COA
