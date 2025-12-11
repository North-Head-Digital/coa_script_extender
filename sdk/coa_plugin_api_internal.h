/**
 * COA Script Extender - Plugin API Internal Header
 * 
 * Internal declarations for the plugin API - used by core extender code.
 * Plugins should use coa_plugin_api.h instead.
 */

#pragma once

#include "coa_plugin_api.h"

// Forward declare without conflicting with COA::Lua::lua_State
struct lua_State_internal;

namespace COA {
namespace PluginAPI {

// Initialize the plugin API (called from main extender init)
bool Initialize(uintptr_t gameBase);

// Shutdown the plugin API
void Shutdown();

// Check if initialized
bool IsInitialized();

// Get the Plugin API table
const COA_PluginAPI* GetAPI();

// Load all plugin DLLs from mods folder
void LoadAllPlugins();

// Unload all plugins
void UnloadAllPlugins();

// Call tick on all plugins
void TickAllPlugins(float deltaTime);

// Register plugin functions to Lua (called after COA_Extender table is created)
// Uses void* to avoid type conflicts with different lua_State typedefs
void RegisterPluginFunctionsToLua(void* L);

// Event dispatch functions
bool DispatchEvent(const COA_EventData* data);
void DispatchTick(float deltaTime, double gameTime);
void DispatchLuaLoaded(void* L);

} // namespace PluginAPI
} // namespace COA
