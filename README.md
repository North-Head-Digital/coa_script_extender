# Call to Arms: Gates of Hell - Script Extender

A modding framework for Call to Arms: Gates of Hell - Ostfront that allows deep game modifications through function hooking.

## Features

- **2,100+ discovered functions** mapped from the game binary
- **Hook any game function** using MinHook
- **Full SDK** with typed structures for units, vehicles, weapons, etc.
- **Mod loader** that automatically loads DLLs from a `mods` folder
- **Example mod** demonstrating damage, accuracy, and AI modifications

## Requirements

### Windows (Native Build)
- Windows 10/11 (64-bit)
- Visual Studio 2019 or 2022 with C++ workload
- CMake 3.20+

### Ubuntu (Cross-Compile)
- Ubuntu 20.04+ or similar
- MinGW-w64 cross-compiler
- CMake 3.20+
- Git

```bash
sudo apt update
sudo apt install mingw-w64 cmake build-essential git
```

## Building

### Ubuntu (Cross-Compile) - Recommended

```bash
# Install dependencies if not already installed
sudo apt install mingw-w64 cmake build-essential git

# Build
./build.sh

# Or for a clean build
./build.sh --clean

# Debug build
./build.sh --debug
```

Output will be in `build/coa_extender.dll` and `build/mods/example_mod.dll`

### Windows (Native)

```bash
# Create build directory
mkdir build
cd build

# Generate Visual Studio solution
cmake .. -G "Visual Studio 17 2022" -A x64

# Build
cmake --build . --config Release
```

## Installation

1. Copy `coa_extender.dll` to your game folder (next to the game .exe)
2. Create a `mods` folder in the same location
3. Copy mod DLLs to the `mods` folder
4. Inject `coa_extender.dll` into the game process (see Injection below)

## Injection Methods

### Method 1: DLL Hijacker
Rename `coa_extender.dll` to a DLL the game loads (e.g., `version.dll`, `winmm.dll`) and place a proxy that loads both.

### Method 2: Manual Injection
Use a DLL injector like:
- [Extreme Injector](https://github.com/master131/ExtremeInjector)
- [Process Hacker](https://processhacker.sourceforge.io/)

### Method 3: Loader Executable
Create a launcher that starts the game suspended, injects the DLL, then resumes.

## Creating Mods

### Minimal Mod Template

```cpp
#include "coa_sdk.h"
#include "coa_hooks.h"

extern "C" {
    __declspec(dllexport) bool ModInit() {
        // Your initialization code here
        return true;
    }
    
    __declspec(dllexport) void ModShutdown() {
        // Cleanup code here
    }
}
```

### Hooking Functions

```cpp
#include "coa_hooks.h"

// Declare original function pointer
static COA::Hooks::AIUpdate_t OriginalAIUpdate = nullptr;

// Your hook function
void MyAIUpdate(COA::AIController* ai, float deltaTime) {
    // Custom logic before
    
    // Call original
    OriginalAIUpdate(ai, deltaTime);
    
    // Custom logic after
}

bool ModInit() {
    // Install the hook
    COA::Hooks::Install(
        COA::Hooks::AI_UPDATE,
        (void*)MyAIUpdate,
        (void**)&OriginalAIUpdate
    );
    return true;
}
```

### Accessing Game Data

```cpp
#include "coa_sdk.h"

void MyFunction() {
    // Get all units
    COA::ForEachUnit([](COA::Unit* unit, void* data) {
        if (unit->IsAlive()) {
            // Do something with the unit
            unit->health = unit->maxHealth; // Full heal
        }
    }, nullptr);
    
    // Get player team
    COA::Team* player = COA::GetPlayerTeam();
    if (player) {
        player->manpower += 100;
    }
}
```

## SDK Reference

### Structures

| Structure | Description |
|-----------|-------------|
| `COA::Unit` | Infantry soldier |
| `COA::Vehicle` | Tanks, trucks, etc. |
| `COA::Weapon` | Guns, cannons |
| `COA::Squad` | Group of units |
| `COA::Team` | Player/AI faction |
| `COA::AIController` | AI state machine |
| `COA::GameWorld` | Global game state |

### Key Offsets (from `coa_hooks.h`)

| Function | Offset | Description |
|----------|--------|-------------|
| `AI_UPDATE` | 0x02419f0 | Main AI tick |
| `AI_PATHFINDING` | 0x07e81b0 | Pathfinding system |
| `AI_COMBAT_SYSTEM` | 0x00a0b90 | Combat decisions |
| `AI_TARGET_SELECTION` | 0x0afbbc0 | Target picking |
| `PARSE_DAMAGE_STATS` | 0x07ddd90 | Damage calculation |
| `AI_MORALE_BREAK` | 0x0d752e0 | Morale failure |

See `coa_ai_master_hooks.txt` for the complete list of 1,900+ hook points.

## File Structure

```
coa_script_extender/
├── sdk/
│   ├── coa_sdk.h          # Main SDK header
│   ├── coa_hooks.h        # Hook definitions
│   └── coa_loader.cpp     # DLL loader
├── mods/
│   └── example_mod.cpp    # Example mod
├── CMakeLists.txt         # Build configuration
├── README.md              # This file
│
├── coa_ai_master_hooks.txt       # All discovered hooks
├── coa_ai_master_functions.txt   # All discovered functions
├── coa_structures.h              # Raw structure offsets
└── *.txt                         # Analysis outputs
```

## Discovered Function Categories

| Category | Count | Examples |
|----------|-------|----------|
| AI Controllers | 63 | AI_Controller, AI_FSM |
| Pathfinding | 43 | AI_Pathfinding, AI_Waypoint |
| Movement | 112 | AI_Movement, AI_Driver |
| Combat | 56 | AI_Attack, AI_Defense |
| Vehicle | 40 | AI_Vehicle_Controller |
| Squad/Team | 93 | AI_Squad, AI_Team |
| Morale | 20+ | AI_Morale, AI_Retreat |
| Sensing | 25+ | AI_Detection, AI_Awareness |
| Scripting | 50+ | Script_Event, Script_Trigger |
| Damage | 15 | Parse_Damage_Stats |
| Weapons | 30+ | Parse_Weapon_*, Parse_Fire |

**Total: 2,100+ mapped functions**

## Known Limitations

1. **Structure offsets are approximate** - Field types may not be exactly correct
2. **Some functions may crash** if called with wrong parameters
3. **Game updates may break offsets** - Will need re-analysis after patches
4. **Multiplayer may have anti-cheat** - Use at your own risk

## Contributing

1. Run more Ghidra analysis scripts to discover new functions
2. Document function parameters and return values
3. Create more example mods
4. Improve structure definitions with correct types

## License

MIT License - Use freely for personal modding projects.

## Credits

- Ghidra scripts for function discovery
- MinHook for function hooking
- The Call to Arms modding community
