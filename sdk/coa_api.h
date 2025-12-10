/**
 * Call to Arms: Gates of Hell - Script Extender API
 * 
 * High-level API for mod developers.
 * These functions provide safe, easy-to-use access to game systems.
 * 
 * USAGE:
 *   #include "coa_api.h"
 *   
 *   // In your mod init:
 *   COA_Initialize();
 *   
 *   // Get game state:
 *   auto units = COA_GetAllUnits();
 */

#pragma once

#include "coa_sdk.h"
#include "coa_hooks.h"
#include <vector>
#include <functional>
#include <string>

// Bring COA types into scope for the API
using COA::Unit;
using COA::Vehicle;
using COA::Weapon;
using COA::Squad;
using COA::Team;
using COA::AIController;
using COA::GameWorld;

//=============================================================================
// VERSION INFO
//=============================================================================

#define COA_EXTENDER_VERSION_MAJOR 1
#define COA_EXTENDER_VERSION_MINOR 0
#define COA_EXTENDER_VERSION_PATCH 0
#define COA_EXTENDER_VERSION_STRING "1.0.0"

//=============================================================================
// CALLBACK TYPES
//=============================================================================

// Damage callback - return modified damage value
using DamageCallback = std::function<float(Unit*, float, Unit*, int)>;

// AI Update callback - called every AI tick
using AIUpdateCallback = std::function<void(void*, float)>;

// Unit spawn callback
using UnitSpawnCallback = std::function<void(Unit*)>;

// Command callback - for custom console commands
using CommandCallback = std::function<void(const std::string&, const std::vector<std::string>&)>;

// Generic event callback
using EventCallback = std::function<void(const char* eventName, void* eventData)>;

//=============================================================================
// INITIALIZATION
//=============================================================================

bool COA_Initialize();
void COA_Shutdown();
bool COA_IsInitialized();
const char* COA_GetVersionString();
uintptr_t COA_GetGameBase();

//=============================================================================
// GAME STATE ACCESS
//=============================================================================

void* COA_GetGameManager();
GameWorld* COA_GetGameWorld();
bool COA_IsInGame();
float COA_GetGameTime();

//=============================================================================
// UNIT ACCESS
//=============================================================================

Unit** COA_GetAllUnits(int* outCount);
Unit** COA_GetUnitsByTeam(int teamId, int* outCount);
Unit** COA_GetSelectedUnits(int* outCount);
Unit* COA_GetUnitById(uint32_t unitId);
float COA_GetUnitHealth(Unit* unit);
void COA_SetUnitHealth(Unit* unit, float health);
void COA_GetUnitPosition(Unit* unit, float* x, float* y, float* z);
void COA_SetUnitPosition(Unit* unit, float x, float y, float z);
void COA_KillUnit(Unit* unit);
bool COA_IsUnitAlive(Unit* unit);
Weapon* COA_GetUnitWeapon(Unit* unit);

//=============================================================================
// SQUAD ACCESS
//=============================================================================

Squad** COA_GetAllSquads(int* outCount);
Squad* COA_GetSquadById(uint32_t squadId);
Unit** COA_GetSquadUnits(Squad* squad, int* outCount);
void COA_GiveSquadOrder(Squad* squad, int orderType, float x, float y, float z);

//=============================================================================
// VEHICLE ACCESS
//=============================================================================

Vehicle** COA_GetAllVehicles(int* outCount);
float COA_GetVehicleHealth(Vehicle* vehicle);
float COA_GetVehicleFuel(Vehicle* vehicle);
void COA_SetVehicleFuel(Vehicle* vehicle, float fuel);
int COA_GetVehicleAmmo(Vehicle* vehicle, int weaponIndex);

//=============================================================================
// DAMAGE SYSTEM
//=============================================================================

int COA_RegisterDamageCallback(DamageCallback callback);
void COA_UnregisterDamageCallback(int handle);
void COA_ApplyDamage(Unit* target, float damage, Unit* attacker);
void COA_SetDamageMultiplier(float multiplier);

//=============================================================================
// AI SYSTEM
//=============================================================================

int COA_RegisterAIUpdateCallback(AIUpdateCallback callback);
void COA_UnregisterAIUpdateCallback(int handle);
void COA_ForceAIRethink(void* aiController);
void COA_SetAIAggression(void* aiController, float level);
void COA_SetUnitAIEnabled(Unit* unit, bool enabled);

//=============================================================================
// SPAWNING
//=============================================================================

Unit* COA_SpawnUnit(const char* typeName, int teamId, float x, float y, float z);
Vehicle* COA_SpawnVehicle(const char* typeName, int teamId, float x, float y, float z);
int COA_RegisterSpawnCallback(UnitSpawnCallback callback);

//=============================================================================
// WEAPON MODIFICATIONS
//=============================================================================

void COA_SetWeaponAccuracyMod(Weapon* weapon, float modifier);
void COA_SetWeaponRangeMod(Weapon* weapon, float modifier);
void COA_SetWeaponReloadMod(Weapon* weapon, float modifier);
void COA_SetWeaponDamageMod(Weapon* weapon, float modifier);

//=============================================================================
// CONSOLE / COMMANDS
//=============================================================================

void COA_RegisterCommand(const char* command, CommandCallback callback);
void COA_ExecuteCommand(const char* command);
void COA_ConsolePrint(const char* message);

//=============================================================================
// EVENTS
//=============================================================================

int COA_RegisterEventCallback(const char* eventName, EventCallback callback);
void COA_UnregisterEventCallback(int handle);
void COA_FireEvent(const char* eventName, void* eventData);

//=============================================================================
// MEMORY ACCESS (Advanced)
//=============================================================================

bool COA_ReadMemory(uintptr_t offset, void* buffer, size_t size);
bool COA_WriteMemory(uintptr_t offset, const void* data, size_t size);
void* COA_GetPointer(uintptr_t offset);

//=============================================================================
// LOGGING
//=============================================================================

void COA_Log(const char* format, ...);
void COA_LogLevel(int level, const char* format, ...);
