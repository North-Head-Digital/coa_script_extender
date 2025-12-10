/**
 * COA Script Extender - Lua Bridge
 * 
 * Exposes extender functions to the game's Lua 5.2 scripting engine.
 * This allows Workshop mod authors to use extender features from Lua.
 * 
 * Usage in Lua:
 *   if COA_Extender then
 *       print("Script Extender v" .. COA_Extender.GetVersion())
 *       COA_Extender.Log("Hello from Lua!")
 *       COA_Extender.SetDamageMultiplier(2.0)
 *   end
 */

#pragma once

#include <cstdint>

namespace COA {
namespace Lua {

// Lua 5.2 types (from lua.h)
typedef struct lua_State lua_State;
typedef double lua_Number;
typedef ptrdiff_t lua_Integer;
typedef int (*lua_CFunction)(lua_State* L);

// Initialize the Lua bridge by hooking into the game's Lua system
bool Initialize();

// Shutdown and cleanup
void Shutdown();

// Check if bridge is active
bool IsActive();

// Get the current Lua state (if available)
lua_State* GetState();

// Manually register our functions into a Lua state
// Call this if you hook a function that has access to lua_State
void RegisterFunctions(lua_State* L);

} // namespace Lua
} // namespace COA
