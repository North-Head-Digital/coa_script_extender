/**
 * Call to Arms: Gates of Hell - Script Extender Hooks
 * 
 * Hook definitions for intercepting game functions.
 * Offsets derived from Ghidra analysis.
 * 
 * Usage:
 *   #include "coa_hooks.h"
 *   
 *   // Hook the damage function
 *   COA::Hooks::Install(COA::Hooks::DAMAGE_APPLY, MyDamageHook);
 */

#pragma once

#include "coa_sdk.h"
#include <functional>

namespace COA {
namespace Hooks {

//=============================================================================
// HOOK OFFSETS (RVA from game base)
// These are the discovered function offsets
//=============================================================================

// ============ AI UPDATE/TICK ============
constexpr uintptr_t AI_UPDATE                    = 0x02419f0;
constexpr uintptr_t AI_UPDATE_2                  = 0x07ae500;
constexpr uintptr_t AI_UPDATE_3                  = 0x09452c0;

// ============ AI STATE MACHINE ============
constexpr uintptr_t AI_STATE_MACHINE             = 0x00a7830;
constexpr uintptr_t AI_FSM                       = 0x037b20;
constexpr uintptr_t AI_FSM_2                     = 0x0780650;
constexpr uintptr_t AI_FSM_3                     = 0x07f27a0;

// ============ PATHFINDING ============
constexpr uintptr_t AI_PATHFINDING               = 0x07e81b0;
constexpr uintptr_t AI_PATHFINDING_2             = 0x0831b60;
constexpr uintptr_t AI_PATHFINDING_3             = 0x08a3210;
constexpr uintptr_t AI_NAVIGATION                = 0x07dd70;
constexpr uintptr_t AI_WAYPOINT_SYSTEM           = 0x0b7fdb0;

// ============ MOVEMENT ============
constexpr uintptr_t AI_MOVEMENT_CONTROLLER       = 0x0195d70;
constexpr uintptr_t AI_MOVEMENT_SYSTEM           = 0x09bd710;
constexpr uintptr_t AI_DRIVER_SYSTEM             = 0x004f3b0;

// ============ COMBAT ============
constexpr uintptr_t AI_COMBAT_SYSTEM             = 0x00a0b90;
constexpr uintptr_t AI_ATTACK_BEHAVIOR           = 0x0b5fa50;
constexpr uintptr_t AI_DEFENSE_BEHAVIOR          = 0x00d5c90;
constexpr uintptr_t AI_TARGET_SELECTION          = 0x0afbbc0;
constexpr uintptr_t AI_COVER_SYSTEM              = 0x0194200;
constexpr uintptr_t AI_THREAT_ASSESSMENT         = 0x0383e20;

// ============ SQUAD/TEAM ============
constexpr uintptr_t AI_SQUAD_BEHAVIOR            = 0x00101d0;
constexpr uintptr_t AI_TEAM_COORDINATION         = 0x0216b60;
constexpr uintptr_t AI_FORMATION_SYSTEM          = 0x00e4ef0;
constexpr uintptr_t AI_GROUP_BEHAVIOR            = 0x09ccbb0;

// ============ MORALE/PSYCHOLOGY ============
constexpr uintptr_t AI_MORALE_BREAK              = 0x0d752e0;
constexpr uintptr_t AI_MORALE_ROUT               = 0x0d7d000;
constexpr uintptr_t AI_RETREAT_LOGIC             = 0x0caa990;

// ============ SENSING/AWARENESS ============
constexpr uintptr_t AI_SENSING                   = 0x0afbbc0;
constexpr uintptr_t AI_DETECTION_SYSTEM          = 0x00483c0;
constexpr uintptr_t AI_SPOTTING_SYSTEM           = 0x055b810;
constexpr uintptr_t AI_ENEMY_TRACKING            = 0x00ef1f0;

// ============ VEHICLE AI ============
constexpr uintptr_t AI_VEHICLE_CONTROLLER        = 0x022fba0;
constexpr uintptr_t AI_VEHICLE_DRIVER            = 0x004f3b0;

// ============ ORDERS/COMMANDS ============
constexpr uintptr_t AI_COMMAND_SYSTEM            = 0x01975b0;
constexpr uintptr_t AI_ORDER_PROCESSING          = 0x0037ea0;
constexpr uintptr_t AI_TASK_SYSTEM               = 0x01c9720;
constexpr uintptr_t AI_OBJECTIVE_HANDLER         = 0x01dd220;

// ============ PLANNING ============
constexpr uintptr_t AI_PLANNING_SYSTEM           = 0x00ae650;
constexpr uintptr_t AI_MANAGER_BRAIN             = 0x0cfac80;

// ============ DAMAGE SYSTEM ============
constexpr uintptr_t PARSE_DAMAGE_STATS           = 0x07ddd90;
constexpr uintptr_t PARSE_DAMAGE_STATS_2         = 0x07dd640;
constexpr uintptr_t PARSE_ARMOR_PENETRATION      = 0x03ec700;
constexpr uintptr_t PARSE_ARMOR_VALUES           = 0x03e90c0;

// ============ WEAPON SYSTEM ============
constexpr uintptr_t PARSE_WEAPON_ACCURACY        = 0x0afbbc0;
constexpr uintptr_t PARSE_WEAPON_RANGE           = 0x07bd2c0;
constexpr uintptr_t PARSE_WEAPON_RECOIL          = 0x095c860;
constexpr uintptr_t PARSE_RELOAD_TIME            = 0x0239b50;
constexpr uintptr_t PARSE_FIRE_MODE              = 0x091f3f0;
constexpr uintptr_t PARSE_EXPLOSIVE_STATS        = 0x073b7d0;

// ============ VEHICLE STATS ============
constexpr uintptr_t PARSE_VEHICLE_SPEED          = 0x098e800;
constexpr uintptr_t PARSE_FUEL_SYSTEM            = 0x047a730;
constexpr uintptr_t PARSE_PHYSICS_MASS           = 0x07202c0;
constexpr uintptr_t PARSE_TURRET_SYSTEM          = 0x048d80;

// ============ UNIT STATS ============
constexpr uintptr_t PARSE_UNIT_HEALTH            = 0x0a4a5c0;
constexpr uintptr_t PARSE_UNIT_STAMINA           = 0x0358f10;
constexpr uintptr_t PARSE_UNIT_VETERANCY         = 0x03b9dd0;
constexpr uintptr_t PARSE_SUPPRESSION            = 0x0b5f980;
constexpr uintptr_t PARSE_PANIC_SYSTEM           = 0x0971500;

// ============ INVENTORY ============
constexpr uintptr_t PARSE_INVENTORY_BASE         = 0x0087cc0;
constexpr uintptr_t PARSE_AMMO_SYSTEM            = 0x0191020;

// ============ ANIMATION ============
constexpr uintptr_t ANIM_ACTION                  = 0x0011a00;
constexpr uintptr_t ANIM_SKELETON                = 0x002f350;
constexpr uintptr_t ANIM_BONE                    = 0x00369f0;

// ============ SCRIPTING ============
constexpr uintptr_t SCRIPT_EVENT                 = 0x0010c50;
constexpr uintptr_t SCRIPT_TRIGGER               = 0x0038260;
constexpr uintptr_t SCRIPT_MESSAGE               = 0x002bd70;
constexpr uintptr_t SCRIPT_SIGNAL                = 0x0038120;

// ============ DIFFICULTY ============
constexpr uintptr_t GAME_DIFFICULTY_NORMAL       = 0x000ff90;
constexpr uintptr_t GAME_DIFFICULTY_MODIFIER     = 0x00279a0;

//=============================================================================
// HOOK TYPES (Function signatures)
//=============================================================================

// AI Update tick (called every frame)
// void AIUpdate(AIController* ai, float deltaTime)
typedef void (*AIUpdate_t)(AIController* ai, float deltaTime);

// Damage application
// float ApplyDamage(Unit* target, float damage, Unit* attacker, Weapon* weapon)
typedef float (*ApplyDamage_t)(Unit* target, float damage, Unit* attacker, Weapon* weapon);

// Target selection
// Unit* SelectTarget(AIController* ai, Unit** potentialTargets, int count)
typedef Unit* (*SelectTarget_t)(AIController* ai, Unit** potentialTargets, int count);

// Pathfinding request
// bool FindPath(Vector3 start, Vector3 end, PathNode** outPath, int* outNodeCount)
typedef bool (*FindPath_t)(Vector3 start, Vector3 end, PathNode** outPath, int* outNodeCount);

// State change
// void OnStateChange(AIController* ai, int oldState, int newState)
typedef void (*OnStateChange_t)(AIController* ai, int oldState, int newState);

// Weapon fire
// bool FireWeapon(Weapon* weapon, Unit* shooter, Vector3 target)
typedef bool (*FireWeapon_t)(Weapon* weapon, Unit* shooter, Vector3 target);

// Vehicle movement
// void UpdateVehicleMovement(Vehicle* vehicle, float throttle, float steering)
typedef void (*VehicleMove_t)(Vehicle* vehicle, float throttle, float steering);

// Morale check
// bool CheckMorale(Unit* unit)
typedef bool (*MoraleCheck_t)(Unit* unit);

// Script event
// void OnScriptEvent(const char* eventName, void* eventData)
typedef void (*ScriptEvent_t)(const char* eventName, void* eventData);

//=============================================================================
// HOOK MANAGEMENT
//=============================================================================

enum class HookResult {
    Continue,       // Let original function run
    Override,       // Skip original, use our return value
    Error           // Hook failed
};

// Hook callback wrapper
template<typename T>
struct HookCallback {
    T originalFunction;
    T hookFunction;
    void* trampolineAddress;
    bool isActive;
};

// Install a hook at the given offset
bool Install(uintptr_t offset, void* hookFunction, void** originalFunction);

// Remove a previously installed hook
bool Remove(uintptr_t offset);

// Check if a hook is installed
bool IsInstalled(uintptr_t offset);

// Enable/disable a hook without removing it
void SetEnabled(uintptr_t offset, bool enabled);

// Get the original function pointer
void* GetOriginal(uintptr_t offset);

// Initialize the hook system (call once at DLL load)
bool Initialize();

// Shutdown the hook system (call at DLL unload)
void Shutdown();

//=============================================================================
// CONVENIENCE MACROS
//=============================================================================

// Declare a hook function with the correct signature
#define COA_DECLARE_HOOK(name, returnType, ...) \
    typedef returnType (*name##_Original_t)(__VA_ARGS__); \
    static name##_Original_t name##_Original = nullptr; \
    static returnType name##_Hook(__VA_ARGS__)

// Install a hook using the convenience macro
#define COA_INSTALL_HOOK(offset, name) \
    COA::Hooks::Install(offset, (void*)&name##_Hook, (void**)&name##_Original)

// Call the original function from within a hook
#define COA_CALL_ORIGINAL(name, ...) \
    (name##_Original ? name##_Original(__VA_ARGS__) : (decltype(name##_Original(__VA_ARGS__)))0)

} // namespace Hooks
} // namespace COA
