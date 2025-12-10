/**
 * Call to Arms: Gates of Hell - Script Extender SDK
 * 
 * Core header file with game structure definitions.
 * These structures were reverse-engineered from the game binary.
 * 
 * Usage:
 *   #include "coa_sdk.h"
 *   
 *   // Access game entities
 *   COA::Unit* unit = COA::GetSelectedUnit();
 *   unit->health = 100.0f;
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <cmath>

// Version string
#define COA_VERSION "1.0.0"

// Game base address (set at runtime)
extern uintptr_t g_GameBase;

// Helper to resolve RVA to actual address
#define COA_RVA(offset) (g_GameBase + (offset))

// Include additional SDK components
#include "coa_globals.h"
#include "coa_vtables.h"
#include "coa_xref_hooks.h"

namespace COA {

//=============================================================================
// FORWARD DECLARATIONS
//=============================================================================

struct Unit;
struct Vehicle;
struct Weapon;
struct Squad;
struct Team;
struct AIController;
struct PathNode;
struct GameWorld;

//=============================================================================
// BASIC TYPES
//=============================================================================

struct Vector3 {
    float x, y, z;
    
    Vector3() : x(0), y(0), z(0) {}
    Vector3(float x_, float y_, float z_) : x(x_), y(y_), z(z_) {}
    
    Vector3 operator+(const Vector3& other) const {
        return Vector3(x + other.x, y + other.y, z + other.z);
    }
    
    Vector3 operator-(const Vector3& other) const {
        return Vector3(x - other.x, y - other.y, z - other.z);
    }
    
    Vector3 operator*(float scalar) const {
        return Vector3(x * scalar, y * scalar, z * scalar);
    }
    
    float Length() const {
        return sqrtf(x*x + y*y + z*z);
    }
    
    float Distance(const Vector3& other) const {
        return (*this - other).Length();
    }
};

struct Vector2 {
    float x, y;
    
    Vector2() : x(0), y(0) {}
    Vector2(float x_, float y_) : x(x_), y(y_) {}
};

struct Quaternion {
    float x, y, z, w;
    
    Quaternion() : x(0), y(0), z(0), w(1) {}
};

struct Matrix4x4 {
    float m[4][4];
};

struct RGBA {
    uint8_t r, g, b, a;
};

//=============================================================================
// ENUMS
//=============================================================================

enum class UnitStance : int32_t {
    Standing = 0,
    Crouching = 1,
    Prone = 2,
    Unknown = -1
};

enum class UnitState : int32_t {
    Idle = 0,
    Moving = 1,
    Attacking = 2,
    Reloading = 3,
    TakingCover = 4,
    Fleeing = 5,
    Dead = 6,
    Unknown = -1
};

enum class VehicleType : int32_t {
    Infantry = 0,
    LightVehicle = 1,
    MediumTank = 2,
    HeavyTank = 3,
    Artillery = 4,
    AntiAir = 5,
    Transport = 6,
    Unknown = -1
};

enum class WeaponType : int32_t {
    Rifle = 0,
    SMG = 1,
    MG = 2,
    Sniper = 3,
    Pistol = 4,
    AT_Rifle = 5,
    Grenade = 6,
    Cannon = 7,
    Unknown = -1
};

enum class TeamSide : int32_t {
    Neutral = 0,
    Axis = 1,
    Allies = 2,
    Soviet = 3,
    Unknown = -1
};

enum class AIBehavior : int32_t {
    Aggressive = 0,
    Defensive = 1,
    Passive = 2,
    HoldPosition = 3,
    Retreat = 4,
    Unknown = -1
};

//=============================================================================
// WEAPON STRUCTURE
//=============================================================================

struct Weapon {
    // Offset 0x00
    void* vtable;
    
    // Offset 0x08 - Basic properties
    uint32_t weaponId;
    WeaponType type;
    
    // Offset 0x10 - Damage stats
    float baseDamage;           // 0x10
    float armorPenetration;     // 0x14
    float explosiveDamage;      // 0x18
    float splashRadius;         // 0x1C
    
    // Offset 0x20 - Accuracy
    float accuracy;             // 0x20
    float spread;               // 0x24
    float recoil;               // 0x28
    float aimTime;              // 0x2C
    
    // Offset 0x30 - Range
    float minRange;             // 0x30
    float maxRange;             // 0x34
    float optimalRange;         // 0x38
    float falloffStart;         // 0x3C
    
    // Offset 0x40 - Reload
    float reloadTime;           // 0x40
    int32_t magazineSize;       // 0x44
    int32_t currentAmmo;        // 0x48
    int32_t reserveAmmo;        // 0x4C
    
    // Offset 0x50 - Fire modes
    float rateOfFire;           // 0x50 (rounds per minute)
    int32_t burstSize;          // 0x54
    float burstDelay;           // 0x58
    uint32_t fireMode;          // 0x5C (0=semi, 1=auto, 2=burst)
    
    // Offset 0x60 - Projectile
    float muzzleVelocity;       // 0x60
    float projectileGravity;    // 0x64
    float projectileDrag;       // 0x68
    
    uint8_t _padding[0x94];     // Pad to 0x100
    
    // Methods
    bool CanFire() const { return currentAmmo > 0; }
    bool NeedsReload() const { return currentAmmo == 0 && reserveAmmo > 0; }
    float GetDPS() const { return baseDamage * (rateOfFire / 60.0f); }
};
static_assert(sizeof(Weapon) == 0x100, "Weapon size mismatch");

//=============================================================================
// ARMOR STRUCTURE
//=============================================================================

struct ArmorProfile {
    float front;                // 0x00
    float side;                 // 0x04
    float rear;                 // 0x08
    float top;                  // 0x0C
    float bottom;               // 0x10
    float turretFront;          // 0x14
    float turretSide;           // 0x18
    float turretRear;           // 0x1C
    float turretTop;            // 0x20
    float slopeModifier;        // 0x24 (effective thickness multiplier)
    
    float GetEffectiveArmor(float angle) const {
        // Simple slope calculation
        return front / cosf(angle * 0.0174533f);
    }
};

//=============================================================================
// UNIT STRUCTURE (Infantry)
//=============================================================================

struct Unit {
    // Offset 0x00 - VTable and base
    void* vtable;
    uint64_t entityId;
    
    // Offset 0x10 - Transform
    Vector3 position;           // 0x10
    float _pad1;                // 0x1C
    Quaternion rotation;        // 0x20
    Vector3 velocity;           // 0x30
    float _pad2;                // 0x3C
    
    // Offset 0x40 - Health/Status
    float health;               // 0x40
    float maxHealth;            // 0x44
    float stamina;              // 0x48
    float maxStamina;           // 0x4C
    float morale;               // 0x50
    float maxMorale;            // 0x54
    float suppression;          // 0x58
    float experience;           // 0x5C
    
    // Offset 0x60 - State
    UnitState state;            // 0x60
    UnitStance stance;          // 0x64
    uint32_t flags;             // 0x68
    TeamSide side;              // 0x6C
    
    // Offset 0x70 - AI
    AIController* aiController; // 0x70
    Unit* targetEnemy;          // 0x78
    Vector3 moveTarget;         // 0x80
    float _pad3;                // 0x8C
    
    // Offset 0x90 - Squad/Team
    Squad* squad;               // 0x90
    Team* team;                 // 0x98
    int32_t squadPosition;      // 0xA0
    int32_t teamRole;           // 0xA4
    
    // Offset 0xA8 - Equipment
    Weapon* primaryWeapon;      // 0xA8
    Weapon* secondaryWeapon;    // 0xB0
    Weapon* currentWeapon;      // 0xB8
    int32_t grenadeCount;       // 0xC0
    int32_t smokeCount;         // 0xC4
    
    // Offset 0xC8 - Veterancy
    int32_t veterancyLevel;     // 0xC8
    float veterancyProgress;    // 0xCC
    float accuracyBonus;        // 0xD0
    float damageBonus;          // 0xD4
    float defenseBonus;         // 0xD8
    
    uint8_t _padding[0x24];     // Pad to 0x100
    
    // Methods
    bool IsAlive() const { return health > 0.0f && state != UnitState::Dead; }
    bool IsSuppressed() const { return suppression > 50.0f; }
    bool IsRouting() const { return morale < 20.0f || state == UnitState::Fleeing; }
    float GetHealthPercent() const { return maxHealth > 0 ? (health / maxHealth) * 100.0f : 0.0f; }
    
    void TakeDamage(float amount) {
        health -= amount;
        if (health <= 0) {
            health = 0;
            state = UnitState::Dead;
        }
    }
    
    void Heal(float amount) {
        health += amount;
        if (health > maxHealth) health = maxHealth;
    }
};
static_assert(sizeof(Unit) == 0x100, "Unit size mismatch");

//=============================================================================
// VEHICLE STRUCTURE
//=============================================================================

struct Vehicle {
    // Offset 0x00 - VTable and base
    void* vtable;
    uint64_t entityId;
    
    // Offset 0x10 - Transform
    Vector3 position;           // 0x10
    float _pad1;                // 0x1C
    Quaternion rotation;        // 0x20
    Vector3 velocity;           // 0x30
    float _pad2;                // 0x3C
    
    // Offset 0x40 - Health
    float health;               // 0x40
    float maxHealth;            // 0x44
    float engineHealth;         // 0x48
    float trackHealth;          // 0x4C
    float turretHealth;         // 0x50
    float gunHealth;            // 0x54
    
    // Offset 0x58 - Fuel
    float fuel;                 // 0x58
    float maxFuel;              // 0x5C
    float fuelConsumption;      // 0x60
    
    // Offset 0x64 - Movement
    float currentSpeed;         // 0x64
    float maxSpeed;             // 0x68
    float reverseSpeed;         // 0x6C
    float acceleration;         // 0x70
    float turnRate;             // 0x74
    float mass;                 // 0x78
    
    // Offset 0x7C - Turret
    float turretRotation;       // 0x7C
    float turretRotationSpeed;  // 0x80
    float gunElevation;         // 0x84
    float gunElevationSpeed;    // 0x88
    float minElevation;         // 0x8C
    float maxElevation;         // 0x90
    
    // Offset 0x94 - Type/State
    VehicleType type;           // 0x94
    TeamSide side;              // 0x98
    uint32_t flags;             // 0x9C
    
    // Offset 0xA0 - Armor
    ArmorProfile armor;         // 0xA0 (0x28 bytes)
    
    // Offset 0xC8 - Weapons
    Weapon* mainGun;            // 0xC8
    Weapon* coaxialMG;          // 0xD0
    Weapon* hullMG;             // 0xD8
    Weapon* commanderMG;        // 0xE0
    int32_t mainGunAmmo;        // 0xE8
    int32_t mgAmmo;             // 0xEC
    
    // Offset 0xF0 - Crew
    Unit* commander;            // 0xF0
    Unit* gunner;               // 0xF8
    Unit* driver;               // 0x100
    Unit* loader;               // 0x108
    int32_t crewCount;          // 0x110
    int32_t maxCrew;            // 0x114
    
    // Offset 0x118 - AI
    AIController* aiController; // 0x118
    Vehicle* targetVehicle;     // 0x120
    Unit* targetInfantry;       // 0x128
    Vector3 moveTarget;         // 0x130
    
    uint8_t _padding[0x2C];     // Pad to 0x168
    
    // Methods
    bool IsOperational() const { return health > 0 && engineHealth > 0; }
    bool CanMove() const { return IsOperational() && fuel > 0 && trackHealth > 0; }
    bool CanFire() const { return gunHealth > 0 && mainGun && mainGun->CanFire(); }
    bool HasCrew() const { return crewCount > 0; }
    float GetArmorAtAngle(float angle) const { return armor.GetEffectiveArmor(angle); }
};
static_assert(sizeof(Vehicle) == 0x168, "Vehicle size mismatch");

//=============================================================================
// SQUAD STRUCTURE
//=============================================================================

struct Squad {
    void* vtable;
    uint64_t squadId;
    
    // Members
    Unit* members[12];          // 0x10 - Max 12 units per squad
    int32_t memberCount;        // 0x70
    int32_t maxMembers;         // 0x74
    
    // Leader
    Unit* leader;               // 0x78
    
    // State
    Vector3 centerPosition;     // 0x80
    float _pad1;                // 0x8C
    AIBehavior behavior;        // 0x90
    TeamSide side;              // 0x94
    
    // Formation
    int32_t formationType;      // 0x98
    float formationSpacing;     // 0x9C
    
    // Stats (aggregate)
    float squadMorale;          // 0xA0
    float squadSuppression;     // 0xA4
    int32_t veterancyLevel;     // 0xA8
    
    // Methods
    int GetAliveCount() const {
        int count = 0;
        for (int i = 0; i < memberCount; i++) {
            if (members[i] && members[i]->IsAlive()) count++;
        }
        return count;
    }
    
    bool IsRouting() const { return squadMorale < 20.0f; }
    bool IsWiped() const { return GetAliveCount() == 0; }
};

//=============================================================================
// TEAM STRUCTURE
//=============================================================================

struct Team {
    void* vtable;
    uint64_t teamId;
    
    TeamSide side;              // 0x10
    int32_t playerIndex;        // 0x14
    
    // Resources
    int32_t manpower;           // 0x18
    int32_t munitions;          // 0x1C
    int32_t fuel;               // 0x20
    int32_t commandPoints;      // 0x24
    
    // Units
    Squad** squads;             // 0x28
    int32_t squadCount;         // 0x30
    Vehicle** vehicles;         // 0x38
    int32_t vehicleCount;       // 0x40
    
    // AI
    AIController* teamAI;       // 0x48
    int32_t difficultyLevel;    // 0x50
};

//=============================================================================
// AI CONTROLLER STRUCTURE
//=============================================================================

struct AIController {
    void* vtable;
    
    // Owner
    void* owner;                // 0x08 (Unit* or Vehicle*)
    uint32_t ownerType;         // 0x10 (0=unit, 1=vehicle, 2=squad, 3=team)
    
    // State machine
    int32_t currentState;       // 0x14
    int32_t previousState;      // 0x18
    float stateTimer;           // 0x1C
    
    // Behavior
    AIBehavior behavior;        // 0x20
    int32_t aggressionLevel;    // 0x24 (0-100)
    int32_t cautiousness;       // 0x28 (0-100)
    
    // Targeting
    void* currentTarget;        // 0x30
    Vector3 lastKnownEnemyPos;  // 0x38
    float _pad1;                // 0x44
    float targetPriority;       // 0x48
    float engageRange;          // 0x4C
    
    // Pathfinding
    PathNode* currentPath;      // 0x50
    int32_t pathNodeCount;      // 0x58
    int32_t currentPathIndex;   // 0x5C
    Vector3 destination;        // 0x60
    float _pad2;                // 0x6C
    
    // Timers
    float thinkInterval;        // 0x70
    float lastThinkTime;        // 0x74
    float reactionTime;         // 0x78
    
    // Flags
    uint32_t aiFlags;           // 0x7C
    bool isActive;              // 0x80
    bool canAttack;             // 0x81
    bool canMove;               // 0x82
    bool canRetreat;            // 0x83
};

//=============================================================================
// PATH NODE
//=============================================================================

struct PathNode {
    Vector3 position;
    float _pad;
    PathNode* next;
    PathNode* prev;
    float cost;
    float heuristic;
    uint32_t flags;
};

//=============================================================================
// GAME WORLD
//=============================================================================

struct GameWorld {
    void* vtable;
    
    // Map info
    float mapWidth;             // 0x08
    float mapHeight;            // 0x0C
    char mapName[64];           // 0x10
    
    // Entity lists
    Unit** allUnits;            // 0x50
    int32_t unitCount;          // 0x58
    Vehicle** allVehicles;      // 0x60
    int32_t vehicleCount;       // 0x68
    Team** teams;               // 0x70
    int32_t teamCount;          // 0x78
    
    // Time
    float gameTime;             // 0x80
    float deltaTime;            // 0x84
    float timeScale;            // 0x88
    bool isPaused;              // 0x8C
    
    // Weather/Environment
    int32_t weatherType;        // 0x90
    float visibility;           // 0x94
    float windSpeed;            // 0x98
    float windDirection;        // 0x9C
};

//=============================================================================
// GLOBAL ACCESSORS (implemented in coa_loader.cpp)
//=============================================================================

// Get the singleton game world
GameWorld* GetGameWorld();

// Get current player's team
Team* GetPlayerTeam();

// Get unit/vehicle by ID
Unit* GetUnitById(uint64_t id);
Vehicle* GetVehicleById(uint64_t id);

// Get currently selected units
Unit** GetSelectedUnits(int* outCount);
Vehicle** GetSelectedVehicles(int* outCount);

// Iterate all entities
typedef void (*UnitCallback)(Unit* unit, void* userData);
typedef void (*VehicleCallback)(Vehicle* vehicle, void* userData);
void ForEachUnit(UnitCallback callback, void* userData);
void ForEachVehicle(VehicleCallback callback, void* userData);

// Spawn/Despawn (if supported)
Unit* SpawnUnit(const char* unitType, Vector3 position, TeamSide side);
Vehicle* SpawnVehicle(const char* vehicleType, Vector3 position, TeamSide side);
void DespawnEntity(uint64_t entityId);

} // namespace COA
