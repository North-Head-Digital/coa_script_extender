/**
 * Call to Arms: Gates of Hell - Global Pointers & Singletons
 * Auto-discovered by GameWorldFinder.java
 * 
 * These are the most referenced global pointers in the game.
 * Access them at runtime: g_GameBase + offset
 */

#pragma once
#include <cstdint>

namespace COA {
namespace Globals {

//=============================================================================
// HIGHLY REFERENCED GLOBALS (Top 30 by reference count)
// These are likely core game managers/singletons
//=============================================================================

// Tier 1: Core System Pointers (1000+ references)
constexpr uintptr_t GLOBAL_CORE_1           = 0x0fe43f0;  // 3232 refs - LIKELY MAIN GAME MANAGER
constexpr uintptr_t GLOBAL_CORE_2           = 0x0fe43e8;  // 2470 refs - Paired with CORE_1
constexpr uintptr_t GLOBAL_CORE_3           = 0x145c020;  // 1419 refs - Data section global
constexpr uintptr_t GLOBAL_VTABLE_BASE      = 0x0fe78d8;  // 1398 refs - Matches top vtable
constexpr uintptr_t GLOBAL_CORE_4           = 0x0fd16d8;  // 1268 refs
constexpr uintptr_t GLOBAL_CORE_5           = 0x148fc10;  // 1031 refs

// Tier 2: Major Subsystem Pointers (500-1000 references)
constexpr uintptr_t GLOBAL_SUBSYS_1         = 0x145c030;  // 943 refs
constexpr uintptr_t GLOBAL_SUBSYS_2         = 0x0fd2218;  // 897 refs
constexpr uintptr_t GLOBAL_SUBSYS_3         = 0x145c038;  // 868 refs
constexpr uintptr_t GLOBAL_SUBSYS_4         = 0x0fe3a50;  // 808 refs
constexpr uintptr_t GLOBAL_SUBSYS_5         = 0x0fd21a0;  // 719 refs
constexpr uintptr_t GLOBAL_SUBSYS_6         = 0x0fe6e68;  // 710 refs
constexpr uintptr_t AI_VTABLE_PTR           = 0x0fe7858;  // 678 refs - AI VTable
constexpr uintptr_t GLOBAL_SUBSYS_7         = 0x0fe7b90;  // 630 refs
constexpr uintptr_t GLOBAL_SUBSYS_8         = 0x0fe79b0;  // 624 refs
constexpr uintptr_t GLOBAL_SUBSYS_9         = 0x146c0c0;  // 618 refs

// Tier 3: Component Pointers (400-600 references)
constexpr uintptr_t GLOBAL_DATA_START       = 0x144c000;  // 566 refs - .data section start
constexpr uintptr_t GLOBAL_COMP_1           = 0x14557b0;  // 555 refs
constexpr uintptr_t GLOBAL_COMP_2           = 0x0fe7c80;  // 545 refs
constexpr uintptr_t GLOBAL_DATA_2           = 0x144c008;  // 539 refs
constexpr uintptr_t GLOBAL_COMP_3           = 0x148fc98;  // 532 refs
constexpr uintptr_t VEHICLE_AI_VTABLE_PTR   = 0x0fe6960;  // 448 refs - Vehicle AI VTable
constexpr uintptr_t GLOBAL_COMP_4           = 0x145c028;  // 433 refs
constexpr uintptr_t GLOBAL_COMP_5           = 0x0fe43d8;  // 431 refs

//=============================================================================
// GETINSTANCE-STYLE SINGLETON ACCESSORS
// These small functions return global pointers
//=============================================================================

// Function addresses that return singletons (call these to get instances)
constexpr uintptr_t GET_SINGLETON_1         = 0x00a4f90;  // Returns 0x0fe38e8
constexpr uintptr_t GET_SINGLETON_2         = 0x00b1b20;  // Returns 0x0fe5378
constexpr uintptr_t GET_SINGLETON_3         = 0x00b1cb0;  // Returns 0x0fe5460
constexpr uintptr_t GET_SINGLETON_4         = 0x00b1db0;  // Returns 0x0fe55c0
constexpr uintptr_t GET_SINGLETON_5         = 0x00b2010;  // Returns 0x0fe5690
constexpr uintptr_t GET_SINGLETON_6         = 0x00b2150;  // Returns 0x0fe5778
constexpr uintptr_t GET_SINGLETON_7         = 0x00b2280;  // Returns 0x0fe5830
constexpr uintptr_t GET_SINGLETON_8         = 0x00b23f0;  // Returns 0x0fe58e0

// Singleton storage locations (where GetInstance stores/retrieves the pointer)
constexpr uintptr_t SINGLETON_PTR_1         = 0x0fe38e8;
constexpr uintptr_t SINGLETON_PTR_2         = 0x0fe5378;
constexpr uintptr_t SINGLETON_PTR_3         = 0x0fe5460;
constexpr uintptr_t SINGLETON_PTR_4         = 0x0fe55c0;
constexpr uintptr_t SINGLETON_PTR_5         = 0x0fe5690;
constexpr uintptr_t SINGLETON_PTR_6         = 0x0fe5778;
constexpr uintptr_t SINGLETON_PTR_7         = 0x0fe5830;
constexpr uintptr_t SINGLETON_PTR_8         = 0x0fe58e0;

//=============================================================================
// NAMED GLOBALS (identified from string context)
//=============================================================================

constexpr uintptr_t GAME_CONTEXT_1          = 0x0fe7830;  // "game" from AI_Enemy_Tracking
constexpr uintptr_t GAME_CONTEXT_2          = 0x0fe7f8c;  // "game" from AI_Threat_Assessment
constexpr uintptr_t MATCH_MANAGER           = 0x0fe5170;  // "match" context
constexpr uintptr_t MATCH_MANAGER_2         = 0x0fe6dfc;  // "match" context
constexpr uintptr_t SCENE_MANAGER           = 0x0fe5e48;  // "scene" context
constexpr uintptr_t MISSION_DATA            = 0x0fedb01;  // "mission" from AI_Team_Coordination
constexpr uintptr_t MISSION_DATA_2          = 0x0fedb84;  // "mission" from AI_Defense_Behavior

//=============================================================================
// CONSTRUCTOR-INITIALIZED SINGLETONS
// Objects that store 'this' to a global in their constructor
//=============================================================================

constexpr uintptr_t CTOR_SINGLETON_1        = 0x1454518;
constexpr uintptr_t CTOR_SINGLETON_2        = 0x1454538;
constexpr uintptr_t CTOR_SINGLETON_3        = 0x1454870;
constexpr uintptr_t CTOR_SINGLETON_4        = 0x1454918;
constexpr uintptr_t CTOR_SINGLETON_5        = 0x1454da0;
constexpr uintptr_t CTOR_SINGLETON_6        = 0x145b6f0;
constexpr uintptr_t CTOR_SINGLETON_7        = 0x145c588;
constexpr uintptr_t CTOR_SINGLETON_8        = 0x145c750;

//=============================================================================
// HELPER FUNCTIONS
//=============================================================================

// Get a global pointer at runtime
template<typename T>
inline T* GetGlobal(uintptr_t gameBase, uintptr_t offset) {
    return *reinterpret_cast<T**>(gameBase + offset);
}

// Get singleton via GetInstance function
template<typename T>
inline T* CallGetInstance(uintptr_t gameBase, uintptr_t funcOffset) {
    typedef T* (*GetInstanceFn)();
    auto fn = reinterpret_cast<GetInstanceFn>(gameBase + funcOffset);
    return fn();
}

} // namespace Globals
} // namespace COA

//=============================================================================
// CONVENIENT ACCESS MACROS
//=============================================================================

// Read a global pointer
#define COA_GET_GLOBAL(T, offset) \
    COA::Globals::GetGlobal<T>(g_GameBase, offset)

// Call a GetInstance function
#define COA_GET_INSTANCE(T, funcOffset) \
    COA::Globals::CallGetInstance<T>(g_GameBase, funcOffset)
