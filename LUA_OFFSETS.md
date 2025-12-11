# Lua Function Offsets - Call to Arms: Gates of Hell v1.059.0

## Game Info
- **Executable**: `coa_goh_ostfront.exe`
- **Build Date**: 2025.12.03 15:16
- **Build Hash**: bf3cd33d5 - 0x01666834
- **Base Address**: 0x140000000
- **Lua Version**: 5.2 (statically linked)

## Status: ✅ WORKING

The Lua bridge is fully operational. `COA_Extender` table successfully registers in `_G` and functions can be called from Lua scripts.

---

## VERIFIED Functions (Currently Used)

| Function | Offset | RVA | Status |
|----------|--------|-----|--------|
| `lua_pushcclosure` | `0x00D6AB20` | `0x140D6AB20` | ✅ Hooked for lua_State capture |
| `lua_createtable` | `0x00D69D40` | `0x140D69D40` | ✅ Working - creates tables |
| `lua_setfield` | `0x00D6B670` | `0x140D6B670` | ✅ Working - sets table fields |
| `lua_settop` | `0x00D6B9B0` | `0x140D6B9B0` | ✅ Working - stack manipulation |
| `lua_gettop` | `0x00D6FD10` | `0x140D6FD10` | ✅ Working - gets stack top |
| `lua_rawgeti` | `0x00D6B0B0` | `0x140D6B0B0` | ✅ Working - registry access |
| `luaL_setfuncs` | `0x00D6E580` | `0x140D6E580` | ✅ Working - bulk function registration |
| `lua_pushstring` | `0x00D7AC60` | `0x140D7AC60` | ✅ Working |
| `lua_pushnumber` | `0x00D7A470` | `0x140D7A470` | ✅ Working |
| `lua_pushinteger` | `0x00D7A440` | `0x140D7A440` | ✅ Working |
| `lua_pushboolean` | `0x00D7A4B0` | `0x140D7A4B0` | ✅ Working |
| `lua_toboolean` | `0x00D6F550` | `0x140D6F550` | ✅ Working |
| `lua_tonumberx` | `0x00D6F3D0` | `0x140D6F3D0` | ✅ Working |
| `lua_tolstring` | `0x00D7A290` | `0x140D7A290` | ✅ Working |
| `lua_type` | `0x00D6F630` | `0x140D6F630` | ✅ Working |
| `lua_pcall` | `0x00D712A0` | `0x140D712A0` | ✅ Hooked |

## Internal Functions (Reference Only)

| Function | Offset | Notes |
|----------|--------|-------|
| `luaH_new` | `0x00D77210` | Internal - creates Table object |
| `luaH_resize` | `0x00D77E80` | Internal - resizes hash tables |
| `luaV_execute` | `0x00D7B070` | VM interpreter (4826 bytes) |
| `lua_resume` | `0x00D71420` | Coroutine resume |

## Historical Notes

The original `lua_createtable` offset was incorrectly identified as `0x00D77E80`, which is actually `luaH_resize`. This caused crashes when trying to register tables. The correct offset `0x00D69D40` was found using `FindLuaCreateTable.java`.

---

## Constants

| Constant | Value | Notes |
|----------|-------|-------|
| `LUA_REGISTRYINDEX` | `-1001000` | Registry pseudo-index |
| `LUA_RIDX_GLOBALS` | `2` | `_G` is at `registry[2]` |
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
