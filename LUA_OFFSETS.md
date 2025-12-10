# Lua Function Offsets - Call to Arms: Gates of Hell v1.059.0

## Game Info
- **Executable**: `coa_goh_ostfront.exe`
- **Build Date**: 2025.12.03 15:16
- **Build Hash**: bf3cd33d5 - 0x01666834
- **Base Address**: 0x140000000
- **Lua Version**: 5.2 (statically linked)

---

## VERIFIED Functions (via Ghidra reverse engineering)

### Core Lua API

| Function | Offset | RVA | Signature | Notes |
|----------|--------|-----|-----------|-------|
| `lua_pushcclosure` | `0x00D6AB20` | `0x140D6AB20` | `void(L, fn, n)` | ✅ Verified - creates C closures |
| `luaV_execute` | `0x00D7B070` | `0x140D7B070` | `void(L)` | ✅ Verified - main VM interpreter, 4826 bytes |
| `lua_resume` | `0x00D71420` | `0x140D71420` | `int(L, from, nargs)` | ✅ Verified - "cannot resume" strings |
| `luaH_new` | `0x00D77210` | `0x140D77210` | `Table*(L)` | ✅ Verified - creates table object |
| `luaH_resize` | `0x00D77E80` | `0x140D77E80` | `void(L, t, nasize, nhsize)` | ✅ Verified - "table overflow" string |
| `luaL_setfuncs` | `0x00D6E580` | `0x140D6E580` | `void(L, l, nup)` | ✅ Verified - registers function array |

### WRONG Offsets (DO NOT USE)

| Function | Wrong Offset | Correct Info |
|----------|--------------|--------------|
| `lua_createtable` | `0x00D77E80` | ❌ This is `luaH_resize`! Need to find real one |

---

## UNVERIFIED Functions (need Ghidra verification)

| Function | Guessed Offset | Status |
|----------|----------------|--------|
| `lua_createtable` | TBD | Need to find - calls luaH_new + pushes to stack |
| `lua_setfield` | `0x00D76D50` | Unverified |
| `lua_setglobal` | `0x00D773F0` | Unverified |
| `lua_gettop` | `0x00D6FD10` | Unverified |
| `lua_settop` | `0x00D6F090` | Unverified |
| `lua_type` | `0x00D6F630` | Unverified |
| `lua_pushstring` | `0x00D7AC60` | Unverified |
| `lua_pcall` | `0x00D712A0` | Unverified - might be lua_pcallk |

---

## String References Found

| String | Address | Used By |
|--------|---------|---------|
| `"too many upvalues"` | `0x1411372a8` | `luaL_setfuncs` (error check) |
| `"stack overflow (%s)"` | `0x1411371a0` | `luaL_setfuncs` |
| `"C stack overflow"` | `0x141137xxx` | `lua_resume` |
| `"cannot resume non-suspended coroutine"` | `0x141137xxx` | `lua_resume` |
| `"cannot resume dead coroutine"` | `0x141137xxx` | `lua_resume` |
| `"table overflow"` | `0x141138xxx` | `luaH_resize` |
| `"upvalue"` | `0x1411382e8` | debug functions |
| `"getupvalue"` | `0x141139800` | debug.getupvalue |
| `"setupvalue"` | `0x141139858` | debug.setupvalue |
| `"invalid upvalue index"` | `0x141139998` | debug functions |

---

## Current Issue

We can hook `lua_pushcclosure` and capture `lua_State*` successfully, but when we try to call `lua_createtable` to register our `COA_Extender` table, the game crashes.

**Crash Details:**
- RIP: `0x140d77f0b` (inside luaH_resize at `0x140d77e80`)
- Exception: `EXCEPTION_ACCESS_VIOLATION write at 0x00000020`
- This means we're calling the wrong function - `luaH_resize` expects a `Table*` as second param, not creating one

**Solution Needed:**
Find the real `lua_createtable` which should:
1. Take signature `(lua_State* L, int narray, int nrec)`
2. Call `luaH_new` internally
3. Push the new table onto the Lua stack

---

## Ghidra Analysis Tips

### Finding Lua Functions
1. Search for error message strings (e.g., "stack overflow", "too many upvalues")
2. Find references to those strings
3. The referencing function is usually the Lua API function

### Signature Patterns
- `lua_State*` is always first parameter
- `lua_State` has `top` pointer at offset `+0x10`
- Functions that push values write to `L->top` then increment it

### Key Internal Types
- `TValue` = 16 bytes (8 byte value + 4 byte type tag + 4 padding)
- `Table` = referenced at offsets 0x18, 0x20, 0x28 for array/hash parts
- `CClosure` = has function pointer at offset +0x18, type tag 0x66

---

## Files to Review

- `sdk/coa_lua_bridge.cpp` - Main Lua bridge implementation
- `ghidra_scripts/FindLuaExecute.java` - Ghidra script for finding Lua functions
- `coa_function_map.txt` - Original function offset guesses
- `coa_structures.h` - Game structure definitions

---

## How to Help

1. Open `coa_goh_ostfront.exe` in Ghidra
2. Run full analysis
3. Find the functions marked as "TBD" above
4. Verify by checking function signature and behavior
5. Update this file with findings
