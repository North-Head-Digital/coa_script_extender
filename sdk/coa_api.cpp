/**
 * Call to Arms: Gates of Hell - Script Extender API Implementation
 */

#include "coa_api.h"
#include "MinHook.h"
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <vector>
#include <map>
#include <mutex>
#include <string>

// Use the COA namespace types
using namespace COA;

//=============================================================================
// INTERNAL STATE
//=============================================================================

static bool g_Initialized = false;
static FILE* g_LogFile = nullptr;
static std::mutex g_Mutex;

// Callback storage
static std::vector<DamageCallback> g_DamageCallbacks;
static std::vector<AIUpdateCallback> g_AIUpdateCallbacks;
static std::vector<UnitSpawnCallback> g_SpawnCallbacks;
static std::map<std::string, CommandCallback> g_CommandCallbacks;
static std::map<std::string, std::vector<EventCallback>> g_EventCallbacks;

// Modifiers
static float g_DamageMultiplier = 1.0f;

// Original function pointers (for hooks)
static void* g_OriginalAIUpdate = nullptr;
static void* g_OriginalApplyDamage = nullptr;

//=============================================================================
// LOGGING
//=============================================================================

static void InitLog() {
    if (g_LogFile) return;
    
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    
    char* lastSlash = strrchr(path, '\\');
    if (lastSlash) {
        strcpy(lastSlash + 1, "coa_extender.log");
    }
    
    g_LogFile = fopen(path, "w");
    if (g_LogFile) {
        fprintf(g_LogFile, "=== COA Script Extender v%s ===\n", COA_EXTENDER_VERSION_STRING);
        fflush(g_LogFile);
    }
}

void COA_Log(const char* format, ...) {
    if (!g_LogFile) return;
    
    std::lock_guard<std::mutex> lock(g_Mutex);
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_LogFile, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    
    va_list args;
    va_start(args, format);
    vfprintf(g_LogFile, format, args);
    va_end(args);
    
    fprintf(g_LogFile, "\n");
    fflush(g_LogFile);
}

void COA_LogLevel(int level, const char* format, ...) {
    if (!g_LogFile) return;
    
    const char* levelStr[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    if (level < 0 || level > 3) level = 1;
    
    std::lock_guard<std::mutex> lock(g_Mutex);
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_LogFile, "[%02d:%02d:%02d] [%s] ", st.wHour, st.wMinute, st.wSecond, levelStr[level]);
    
    va_list args;
    va_start(args, format);
    vfprintf(g_LogFile, format, args);
    va_end(args);
    
    fprintf(g_LogFile, "\n");
    fflush(g_LogFile);
}

//=============================================================================
// HOOK TRAMPOLINES
//=============================================================================

// AI Update hook
typedef void (*AIUpdate_fn)(void* ai, float dt);
static AIUpdate_fn Original_AIUpdate = nullptr;

static void Hooked_AIUpdate(void* ai, float dt) {
    // Call registered callbacks
    for (auto& cb : g_AIUpdateCallbacks) {
        cb(ai, dt);
    }
    // Call original
    if (Original_AIUpdate) {
        Original_AIUpdate(ai, dt);
    }
}

// Damage hook
typedef float (*ApplyDamage_fn)(void* target, float damage, void* attacker, int weaponType);
static ApplyDamage_fn Original_ApplyDamage = nullptr;

static float Hooked_ApplyDamage(void* target, float damage, void* attacker, int weaponType) {
    float modifiedDamage = damage * g_DamageMultiplier;
    
    // Call registered callbacks
    for (auto& cb : g_DamageCallbacks) {
        modifiedDamage = cb((::Unit*)target, modifiedDamage, (::Unit*)attacker, weaponType);
    }
    
    // Call original with modified damage
    if (Original_ApplyDamage) {
        return Original_ApplyDamage(target, modifiedDamage, attacker, weaponType);
    }
    return modifiedDamage;
}

//=============================================================================
// INITIALIZATION
//=============================================================================

bool COA_Initialize() {
    if (g_Initialized) {
        return true;
    }
    
    InitLog();
    COA_Log("Initializing COA Script Extender v%s", COA_EXTENDER_VERSION_STRING);
    
    // Get game base address
    g_GameBase = (uintptr_t)GetModuleHandleA(nullptr);
    if (g_GameBase == 0) {
        COA_Log("ERROR: Failed to get game base address");
        return false;
    }
    COA_Log("Game base: 0x%llX", (unsigned long long)g_GameBase);
    
    // Initialize MinHook
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED) {
        COA_Log("ERROR: MinHook init failed: %d", status);
        return false;
    }
    COA_Log("MinHook initialized");
    
    // Install core hooks
    void* target;
    
    // AI Update hook
    target = (void*)(g_GameBase + Hooks::AI_UPDATE);
    status = MH_CreateHook(target, (void*)Hooked_AIUpdate, (void**)&Original_AIUpdate);
    if (status == MH_OK) {
        MH_EnableHook(target);
        COA_Log("Installed AI Update hook at 0x%llX", (unsigned long long)Hooks::AI_UPDATE);
    } else {
        COA_Log("WARNING: AI Update hook failed: %d", status);
    }
    
    g_Initialized = true;
    COA_Log("Initialization complete");
    
    return true;
}

void COA_Shutdown() {
    if (!g_Initialized) return;
    
    COA_Log("Shutting down...");
    
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    
    g_DamageCallbacks.clear();
    g_AIUpdateCallbacks.clear();
    g_SpawnCallbacks.clear();
    g_CommandCallbacks.clear();
    g_EventCallbacks.clear();
    
    if (g_LogFile) {
        COA_Log("Shutdown complete");
        fclose(g_LogFile);
        g_LogFile = nullptr;
    }
    
    g_Initialized = false;
}

bool COA_IsInitialized() {
    return g_Initialized;
}

const char* COA_GetVersionString() {
    return COA_EXTENDER_VERSION_STRING;
}

uintptr_t COA_GetGameBase() {
    return g_GameBase;
}

//=============================================================================
// GAME STATE ACCESS
//=============================================================================

void* COA_GetGameManager() {
    // Use a generic global pointer - needs verification
    void** ptr = (void**)(g_GameBase + 0x0fe43f0);
    return ptr ? *ptr : nullptr;
}

::GameWorld* COA_GetGameWorld() {
    void* manager = COA_GetGameManager();
    if (!manager) return nullptr;
    
    // GameWorld is typically at offset 0x8 or 0x10 in the manager
    ::GameWorld** worldPtr = (::GameWorld**)((uintptr_t)manager + 0x8);
    return worldPtr ? *worldPtr : nullptr;
}

bool COA_IsInGame() {
    ::GameWorld* world = COA_GetGameWorld();
    return world != nullptr;
}

float COA_GetGameTime() {
    ::GameWorld* world = COA_GetGameWorld();
    if (!world) return 0.0f;
    return 0.0f; // TODO: Implement once offset is verified
}

//=============================================================================
// UNIT ACCESS
//=============================================================================

static std::vector<::Unit*> g_UnitCache;
static bool g_UnitCacheDirty = true;

static void RefreshUnitCache() {
    g_UnitCache.clear();
    // TODO: Access the unit list from GameWorld once structure is verified
}

::Unit** COA_GetAllUnits(int* outCount) {
    if (g_UnitCacheDirty) {
        RefreshUnitCache();
        g_UnitCacheDirty = false;
    }
    
    if (outCount) *outCount = (int)g_UnitCache.size();
    return g_UnitCache.empty() ? nullptr : g_UnitCache.data();
}

::Unit** COA_GetUnitsByTeam(int teamId, int* outCount) {
    static std::vector<::Unit*> teamUnits;
    teamUnits.clear();
    
    int totalCount;
    ::Unit** allUnits = COA_GetAllUnits(&totalCount);
    
    for (int i = 0; i < totalCount; i++) {
        ::Unit* unit = allUnits[i];
        if (unit && (int)unit->side == teamId) {
            teamUnits.push_back(unit);
        }
    }
    
    if (outCount) *outCount = (int)teamUnits.size();
    return teamUnits.empty() ? nullptr : teamUnits.data();
}

::Unit** COA_GetSelectedUnits(int* outCount) {
    if (outCount) *outCount = 0;
    return nullptr; // TODO: Implement
}

::Unit* COA_GetUnitById(uint32_t unitId) {
    int count;
    ::Unit** units = COA_GetAllUnits(&count);
    
    for (int i = 0; i < count; i++) {
        if (units[i] && units[i]->entityId == unitId) {
            return units[i];
        }
    }
    return nullptr;
}

float COA_GetUnitHealth(::Unit* unit) {
    if (!unit) return 0.0f;
    return unit->health;
}

void COA_SetUnitHealth(::Unit* unit, float health) {
    if (!unit) return;
    unit->health = health;
    if (health > unit->maxHealth) {
        unit->health = unit->maxHealth;
    }
}

void COA_GetUnitPosition(::Unit* unit, float* x, float* y, float* z) {
    if (!unit) return;
    if (x) *x = unit->position.x;
    if (y) *y = unit->position.y;
    if (z) *z = unit->position.z;
}

void COA_SetUnitPosition(::Unit* unit, float x, float y, float z) {
    if (!unit) return;
    unit->position.x = x;
    unit->position.y = y;
    unit->position.z = z;
}

void COA_KillUnit(::Unit* unit) {
    if (!unit) return;
    unit->health = 0.0f;
    unit->flags |= 0x1; // Dead flag
}

bool COA_IsUnitAlive(::Unit* unit) {
    if (!unit) return false;
    return unit->health > 0.0f && !(unit->flags & 0x1);
}

::Weapon* COA_GetUnitWeapon(::Unit* unit) {
    if (!unit) return nullptr;
    return unit->currentWeapon;
}

//=============================================================================
// DAMAGE SYSTEM
//=============================================================================

static int g_NextCallbackHandle = 1;

int COA_RegisterDamageCallback(DamageCallback callback) {
    std::lock_guard<std::mutex> lock(g_Mutex);
    g_DamageCallbacks.push_back(callback);
    return g_NextCallbackHandle++;
}

void COA_UnregisterDamageCallback(int handle) {
    // TODO: Proper implementation with handle tracking
    (void)handle;
}

void COA_ApplyDamage(::Unit* target, float damage, ::Unit* attacker) {
    if (!target) return;
    
    float finalDamage = damage * g_DamageMultiplier;
    
    for (auto& cb : g_DamageCallbacks) {
        finalDamage = cb(target, finalDamage, attacker, 0);
    }
    
    target->health -= finalDamage;
    if (target->health < 0) target->health = 0;
    
    COA_Log("Applied %.2f damage to unit %llu", finalDamage, (unsigned long long)target->entityId);
}

void COA_SetDamageMultiplier(float multiplier) {
    g_DamageMultiplier = multiplier;
    COA_Log("Damage multiplier set to %.2f", multiplier);
}

//=============================================================================
// AI SYSTEM
//=============================================================================

int COA_RegisterAIUpdateCallback(AIUpdateCallback callback) {
    std::lock_guard<std::mutex> lock(g_Mutex);
    g_AIUpdateCallbacks.push_back(callback);
    return g_NextCallbackHandle++;
}

void COA_UnregisterAIUpdateCallback(int handle) {
    (void)handle;
}

void COA_ForceAIRethink(void* aiController) {
    (void)aiController;
}

void COA_SetAIAggression(void* aiController, float level) {
    (void)aiController;
    (void)level;
}

void COA_SetUnitAIEnabled(::Unit* unit, bool enabled) {
    if (!unit) return;
    if (enabled) {
        unit->flags &= ~0x100;
    } else {
        unit->flags |= 0x100;
    }
}

//=============================================================================
// SPAWNING - PLACEHOLDER
//=============================================================================

::Unit* COA_SpawnUnit(const char* typeName, int teamId, float x, float y, float z) {
    COA_Log("SpawnUnit called: %s at (%.1f, %.1f, %.1f)", typeName, x, y, z);
    (void)teamId;
    return nullptr; // TODO: Implement
}

::Vehicle* COA_SpawnVehicle(const char* typeName, int teamId, float x, float y, float z) {
    COA_Log("SpawnVehicle called: %s at (%.1f, %.1f, %.1f)", typeName, x, y, z);
    (void)teamId;
    return nullptr; // TODO: Implement
}

int COA_RegisterSpawnCallback(UnitSpawnCallback callback) {
    std::lock_guard<std::mutex> lock(g_Mutex);
    g_SpawnCallbacks.push_back(callback);
    return g_NextCallbackHandle++;
}

//=============================================================================
// MEMORY ACCESS
//=============================================================================

bool COA_ReadMemory(uintptr_t offset, void* buffer, size_t size) {
    if (!buffer) return false;
    void* src = (void*)(g_GameBase + offset);
    memcpy(buffer, src, size);
    return true;
}

bool COA_WriteMemory(uintptr_t offset, const void* data, size_t size) {
    if (!data) return false;
    
    void* dst = (void*)(g_GameBase + offset);
    
    DWORD oldProtect;
    if (!VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        COA_Log("ERROR: VirtualProtect failed for write at 0x%llX", (unsigned long long)offset);
        return false;
    }
    
    memcpy(dst, data, size);
    
    VirtualProtect(dst, size, oldProtect, &oldProtect);
    return true;
}

void* COA_GetPointer(uintptr_t offset) {
    return (void*)(g_GameBase + offset);
}

//=============================================================================
// COMMANDS
//=============================================================================

void COA_RegisterCommand(const char* command, CommandCallback callback) {
    std::lock_guard<std::mutex> lock(g_Mutex);
    g_CommandCallbacks[command] = callback;
    COA_Log("Registered command: %s", command);
}

void COA_ExecuteCommand(const char* command) {
    std::string cmdStr(command);
    std::vector<std::string> args;
    
    size_t pos = cmdStr.find(' ');
    std::string cmdName = (pos != std::string::npos) ? cmdStr.substr(0, pos) : cmdStr;
    
    auto it = g_CommandCallbacks.find(cmdName);
    if (it != g_CommandCallbacks.end()) {
        it->second(cmdName, args);
    }
}

void COA_ConsolePrint(const char* message) {
    COA_Log("[Console] %s", message);
}

//=============================================================================
// EVENTS
//=============================================================================

int COA_RegisterEventCallback(const char* eventName, EventCallback callback) {
    std::lock_guard<std::mutex> lock(g_Mutex);
    g_EventCallbacks[eventName].push_back(callback);
    return g_NextCallbackHandle++;
}

void COA_UnregisterEventCallback(int handle) {
    (void)handle;
}

void COA_FireEvent(const char* eventName, void* eventData) {
    std::lock_guard<std::mutex> lock(g_Mutex);
    
    auto it = g_EventCallbacks.find(eventName);
    if (it != g_EventCallbacks.end()) {
        for (auto& cb : it->second) {
            cb(eventName, eventData);
        }
    }
}

//=============================================================================
// SQUAD ACCESS - PLACEHOLDER
//=============================================================================

::Squad** COA_GetAllSquads(int* outCount) {
    if (outCount) *outCount = 0;
    return nullptr;
}

::Squad* COA_GetSquadById(uint32_t squadId) {
    (void)squadId;
    return nullptr;
}

::Unit** COA_GetSquadUnits(::Squad* squad, int* outCount) {
    (void)squad;
    if (outCount) *outCount = 0;
    return nullptr;
}

void COA_GiveSquadOrder(::Squad* squad, int orderType, float x, float y, float z) {
    (void)squad;
    (void)orderType;
    (void)x;
    (void)y;
    (void)z;
}

//=============================================================================
// VEHICLE ACCESS - PLACEHOLDER
//=============================================================================

::Vehicle** COA_GetAllVehicles(int* outCount) {
    if (outCount) *outCount = 0;
    return nullptr;
}

float COA_GetVehicleHealth(::Vehicle* vehicle) {
    (void)vehicle;
    return 0.0f;
}

float COA_GetVehicleFuel(::Vehicle* vehicle) {
    (void)vehicle;
    return 0.0f;
}

void COA_SetVehicleFuel(::Vehicle* vehicle, float fuel) {
    (void)vehicle;
    (void)fuel;
}

int COA_GetVehicleAmmo(::Vehicle* vehicle, int weaponIndex) {
    (void)vehicle;
    (void)weaponIndex;
    return 0;
}

//=============================================================================
// WEAPON MODIFICATIONS - PLACEHOLDER
//=============================================================================

void COA_SetWeaponAccuracyMod(::Weapon* weapon, float modifier) {
    (void)weapon;
    (void)modifier;
}

void COA_SetWeaponRangeMod(::Weapon* weapon, float modifier) {
    (void)weapon;
    (void)modifier;
}

void COA_SetWeaponReloadMod(::Weapon* weapon, float modifier) {
    (void)weapon;
    (void)modifier;
}

void COA_SetWeaponDamageMod(::Weapon* weapon, float modifier) {
    (void)weapon;
    (void)modifier;
}
