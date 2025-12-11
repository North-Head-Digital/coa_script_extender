# COA Script Extender - Modding Guide

Welcome, modder! This guide will help you create plugins that extend the COA Script Extender.

## Overview

The COA Script Extender allows you to:

1. **Register custom Lua functions** - Your C++ code becomes callable from Lua scripts!
2. **Subscribe to game events** - Get notified when units spawn, die, take damage, etc.
3. **Hook game functions directly** - For advanced reverse-engineering modders

## Quick Start

### 1. Create a new DLL project

Your mod is a standard Windows DLL. Here's the minimal structure:

```cpp
#include "coa_plugin_api.h"

// Store the API for later use
static const COA_PluginAPI* g_API = nullptr;

extern "C" {

__declspec(dllexport) bool ModInit(const COA_PluginAPI* api) {
    g_API = api;
    // Your initialization code here
    return true;
}

__declspec(dllexport) void ModShutdown() {
    // Cleanup code here
}

__declspec(dllexport) void ModTick(float deltaTime) {
    // Called every frame
}

__declspec(dllexport) const char* ModGetName() { return "My Mod"; }
__declspec(dllexport) const char* ModGetVersion() { return "1.0.0"; }
__declspec(dllexport) const char* ModGetAuthor() { return "Your Name"; }

}
```

### 2. Register Lua Functions

This is the exciting part! Your C++ functions become callable from Lua:

```cpp
// Lua API pointer
static const COA_LuaAPI* g_Lua = nullptr;

// Your custom Lua function
static int LuaFunc_SayHello(lua_State* L) {
    if (!g_Lua) return 0;
    
    // Read argument from Lua
    const char* name = g_Lua->lua_tostring(L, 1);
    
    // Log it
    printf("Hello, %s!\n", name ? name : "World");
    
    // Return a string
    g_Lua->lua_pushstring(L, "Hello back!");
    return 1;  // We're returning 1 value
}

// In ModInit:
bool ModInit(const COA_PluginAPI* api) {
    g_API = api;
    g_Lua = api->GetLuaAPI();
    
    // Register our function
    api->RegisterLuaFunction("SayHello", LuaFunc_SayHello);
    
    return true;
}
```

Now in Lua scripts:

```lua
-- Your function is available!
local response = COA_Extender.SayHello("Player")
print(response)  -- Prints "Hello back!"
```

### 3. Namespaced Functions

For organization, put your functions in a custom namespace:

```cpp
api->RegisterNamespacedFunction("MyMod", "GetHealth", LuaFunc_GetHealth);
api->RegisterNamespacedFunction("MyMod", "SetHealth", LuaFunc_SetHealth);
```

In Lua:

```lua
local hp = COA_Plugins.MyMod.GetHealth()
COA_Plugins.MyMod.SetHealth(100)
```

## Lua Function Reference

### Reading Arguments

```cpp
static int MyFunction(lua_State* L) {
    // Arguments are at stack positions 1, 2, 3, etc.
    lua_Number num = g_Lua->lua_tonumber(L, 1);    // First arg as number
    lua_Integer i = g_Lua->lua_tointeger(L, 2);    // Second arg as integer
    const char* s = g_Lua->lua_tostring(L, 3);     // Third arg as string
    int b = g_Lua->lua_toboolean(L, 4);            // Fourth arg as boolean
    
    // ... do something ...
    
    return 0;  // Return 0 values
}
```

### Returning Values

```cpp
static int GetUnitInfo(lua_State* L) {
    // Push return values onto the stack
    g_Lua->lua_pushnumber(L, 100.0);        // Health
    g_Lua->lua_pushstring(L, "Infantry");   // Type
    g_Lua->lua_pushboolean(L, 1);           // IsAlive
    
    return 3;  // We're returning 3 values
}
```

In Lua:

```lua
local health, type, alive = COA_Extender.GetUnitInfo()
```

### Returning Tables

```cpp
static int GetConfig(lua_State* L) {
    // Create a new table
    g_Lua->lua_createtable(L, 0, 3);
    
    // Add fields
    g_Lua->lua_pushnumber(L, 1.5);
    g_Lua->lua_setfield(L, -2, "damageMultiplier");
    
    g_Lua->lua_pushstring(L, "enabled");
    g_Lua->lua_setfield(L, -2, "mode");
    
    g_Lua->lua_pushboolean(L, 1);
    g_Lua->lua_setfield(L, -2, "godMode");
    
    return 1;  // Return the table
}
```

In Lua:

```lua
local config = COA_Extender.GetConfig()
print(config.damageMultiplier)  -- 1.5
print(config.mode)              -- "enabled"
print(config.godMode)           -- true
```

## Event System

Subscribe to game events:

```cpp
static bool OnTick(const COA_EventData* data) {
    float dt = data->tick.deltaTime;
    // Do something every frame
    return true;
}

static bool OnLuaLoaded(const COA_EventData* data) {
    printf("Lua state is ready!\n");
    return true;
}

// In ModInit:
api->SubscribeEvent(COA_EVENT_TICK, OnTick);
api->SubscribeEvent(COA_EVENT_LUA_LOADED, OnLuaLoaded);
```

### Available Events

| Event | Description | Data |
|-------|-------------|------|
| `COA_EVENT_GAME_STARTED` | Game started | - |
| `COA_EVENT_GAME_ENDED` | Game ended | - |
| `COA_EVENT_TICK` | Every frame | `data->tick.deltaTime` |
| `COA_EVENT_UNIT_SPAWNED` | Unit created | `data->unit.unit` |
| `COA_EVENT_UNIT_KILLED` | Unit killed | `data->unit.unit` |
| `COA_EVENT_UNIT_DAMAGED` | Unit damaged | `data->damage.*` |
| `COA_EVENT_VEHICLE_SPAWNED` | Vehicle created | `data->vehicle.vehicle` |
| `COA_EVENT_LUA_LOADED` | Lua ready | `data->lua.state` |

## Direct Game Hooking

For advanced modders who want to hook game functions directly:

```cpp
#include "MinHook.h"
#include "coa_hooks.h"  // Contains known function offsets

typedef float (*ApplyDamage_t)(void*, float, void*, int);
static ApplyDamage_t Original_ApplyDamage = nullptr;

static float Hooked_ApplyDamage(void* target, float damage, void* attacker, int type) {
    // Modify damage before it's applied!
    damage *= 2.0f;
    return Original_ApplyDamage(target, damage, attacker, type);
}

// In ModInit:
uintptr_t gameBase = api->GetGameBase();

MH_Initialize();
MH_CreateHook(
    (void*)(gameBase + COA::Hooks::APPLY_DAMAGE),
    (void*)Hooked_ApplyDamage,
    (void**)&Original_ApplyDamage
);
MH_EnableHook((void*)(gameBase + COA::Hooks::APPLY_DAMAGE));
```

## Building Your Mod

### Requirements

- MinGW-w64 or Visual Studio 2019+
- MinHook (if hooking game functions)
- SDK headers: `coa_sdk.h`, `coa_hooks.h`, `coa_plugin_api.h`

### CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.20)
project(MyMod)

set(CMAKE_CXX_STANDARD 17)

add_library(my_mod SHARED
    my_mod.cpp
)

target_include_directories(my_mod PRIVATE
    path/to/coa_sdk
)

# If using MinHook for game function hooking
target_link_libraries(my_mod PRIVATE
    minhook
)

set_target_properties(my_mod PROPERTIES
    OUTPUT_NAME "my_mod"
    SUFFIX ".dll"
)
```

### Installation

1. Build your DLL
2. Copy it to the `mods` folder in the game directory
3. Launch the game - your mod loads automatically!

## Example: Complete Mod

See `mods/example_mod.cpp` for a complete working example that demonstrates:

- Registering 5 Lua functions
- Registering namespaced functions
- Subscribing to events
- Hooking game functions (optional)
- Returning tables from Lua functions

## Debugging Tips

1. Your mod writes a log file to `mods/your_mod.log`
2. The extender writes to `coa_extender.log` in the game directory
3. Use `COA_Extender.Log("message")` from Lua to log messages
4. Check for errors in the log files if things don't work

## API Version

Current API version: **1**

The API is designed for forward compatibility. Check `api->version` in ModInit if you need specific features.

## Questions?

Open an issue on the GitHub repository!

---

Happy modding! 🎮
