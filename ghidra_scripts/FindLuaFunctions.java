//Find Lua 5.2 function addresses for the Lua bridge
//@author COA Script Extender
//@category COA.Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import java.util.*;

public class FindLuaFunctions extends GhidraScript {

    // Known Lua 5.2 function signatures and associated strings
    private static final String[] LUA_MARKERS = {
        "lua_pushnil",
        "lua_pushnumber", 
        "lua_pushinteger",
        "lua_pushstring",
        "lua_pushboolean",
        "lua_pushcclosure",
        "lua_createtable",
        "lua_setfield",
        "lua_setglobal",
        "lua_getglobal",
        "lua_settop",
        "lua_gettop",
        "lua_type",
        "lua_tonumberx",
        "lua_tointegerx",
        "lua_tolstring",
        "lua_toboolean",
        "lua_pcallk",
        "luaL_error",
        "luaL_newstate",
        "luaopen_base",
        "luaopen_table",
        "luaopen_string"
    };
    
    // Strings that appear near Lua functions
    private static final String[] LUA_STRINGS = {
        "attempt to yield",
        "stack overflow",
        "nil or table expected",
        "table index is nil",
        "table index is NaN",
        "invalid option",
        "'for' initial value",
        "'for' limit",
        "'for' step",
        "bad argument",
        "value expected",
        "_G",
        "_VERSION",
        "Lua 5.2"
    };

    @Override
    protected void run() throws Exception {
        println("=== Finding Lua 5.2 Functions ===");
        println("");
        
        Map<String, Address> foundFunctions = new HashMap<>();
        Map<String, Address> stringRefs = new HashMap<>();
        
        // First, find known Lua strings
        println("Searching for Lua string references...");
        println("----------------------------------------");
        
        Memory memory = currentProgram.getMemory();
        AddressSetView addrSet = memory.getLoadedAndInitializedAddressSet();
        
        for (String marker : LUA_STRINGS) {
            Address addr = findString(marker);
            if (addr != null) {
                stringRefs.put(marker, addr);
                println(String.format("Found '%s' at 0x%s", marker, addr.toString()));
                
                // Find references to this string
                Reference[] refs = getReferencesTo(addr);
                if (refs.length > 0) {
                    println(String.format("  -> Referenced from %d locations", refs.length));
                    for (int i = 0; i < Math.min(refs.length, 3); i++) {
                        Address refAddr = refs[i].getFromAddress();
                        Function func = getFunctionContaining(refAddr);
                        if (func != null) {
                            println(String.format("     - %s (in %s)", 
                                refAddr.toString(), func.getName()));
                        }
                    }
                }
            }
        }
        
        println("");
        println("Searching for Lua API patterns...");
        println("----------------------------------------");
        
        // Search for error message patterns that indicate specific Lua functions
        
        // lua_type check - look for "nil or table expected"
        Address nilOrTable = findString("nil or table expected");
        if (nilOrTable != null) {
            findFunctionByStringRef(nilOrTable, "lua_type (nearby)", foundFunctions);
        }
        
        // lua_tonumber - look for "number expected"
        Address numExpected = findString("number expected");
        if (numExpected != null) {
            findFunctionByStringRef(numExpected, "lua_tonumber (nearby)", foundFunctions);
        }
        
        // luaL_error - look for "bad argument"
        Address badArg = findString("bad argument");
        if (badArg != null) {
            findFunctionByStringRef(badArg, "luaL_error (nearby)", foundFunctions);
        }
        
        // lua_pushfstring - look for "invalid option"
        Address invalidOpt = findString("invalid option");
        if (invalidOpt != null) {
            findFunctionByStringRef(invalidOpt, "lua_pushfstring (nearby)", foundFunctions);
        }
        
        // Search for lua_State* parameter patterns
        println("");
        println("Analyzing functions with lua_State* patterns...");
        println("----------------------------------------");
        
        // Look for functions that:
        // 1. Have a pointer as first parameter
        // 2. Use specific patterns like accessing offsets +8, +16, etc. (Lua stack)
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        
        int luaCandidates = 0;
        List<Function> candidates = new ArrayList<>();
        
        while (funcIter.hasNext() && luaCandidates < 100) {
            Function func = funcIter.next();
            String name = func.getName();
            
            // Check if function name suggests Lua
            if (name.toLowerCase().contains("lua") || 
                name.toLowerCase().contains("script") ||
                name.contains("L_") ||
                name.startsWith("FUN_14")) {
                
                // Check function body for Lua patterns
                if (hasLuaPatterns(func)) {
                    candidates.add(func);
                    luaCandidates++;
                }
            }
        }
        
        println(String.format("Found %d potential Lua-related functions", candidates.size()));
        
        // Output results
        println("");
        println("========================================");
        println("LUA FUNCTION OFFSETS FOR coa_lua_bridge.cpp");
        println("========================================");
        println("");
        println("// Add these to coa_lua_bridge.cpp ResolveLuaFunctions()");
        println("// Base address: 0x140000000");
        println("");
        
        for (Map.Entry<String, Address> entry : foundFunctions.entrySet()) {
            long offset = entry.getValue().getOffset() - 0x140000000L;
            println(String.format("// %s = 0x%08X", entry.getKey(), offset));
        }
        
        println("");
        println("// Candidate functions to investigate:");
        for (int i = 0; i < Math.min(candidates.size(), 20); i++) {
            Function f = candidates.get(i);
            long offset = f.getEntryPoint().getOffset() - 0x140000000L;
            println(String.format("// %s at 0x%08X", f.getName(), offset));
        }
        
        println("");
        println("========================================");
        println("NEXT STEPS");
        println("========================================");
        println("1. Find 'luaL_newstate' - creates new Lua state");
        println("2. Find 'lua_load' or 'luaL_loadfile' - loads Lua scripts");
        println("3. Hook the script loading to inject our functions");
        println("4. Search for 'lua.start' string - game's Lua init");
        
        // Search specifically for lua.start
        Address luaStart = findString("lua.start");
        if (luaStart != null) {
            println("");
            println("Found 'lua.start' at: " + luaStart.toString());
            Reference[] refs = getReferencesTo(luaStart);
            for (Reference ref : refs) {
                Function func = getFunctionContaining(ref.getFromAddress());
                if (func != null) {
                    long offset = func.getEntryPoint().getOffset() - 0x140000000L;
                    println(String.format("  IMPORTANT: lua.start handler at 0x%08X (%s)", 
                        offset, func.getName()));
                }
            }
        }
        
        println("");
        println("=== Analysis Complete ===");
    }
    
    private Address findString(String str) {
        Memory memory = currentProgram.getMemory();
        byte[] bytes = str.getBytes();
        
        try {
            Address addr = memory.findBytes(
                currentProgram.getMinAddress(),
                bytes,
                null,
                true,
                monitor
            );
            return addr;
        } catch (Exception e) {
            return null;
        }
    }
    
    private void findFunctionByStringRef(Address stringAddr, String name, 
                                          Map<String, Address> results) {
        Reference[] refs = getReferencesTo(stringAddr);
        for (Reference ref : refs) {
            Function func = getFunctionContaining(ref.getFromAddress());
            if (func != null) {
                results.put(name, func.getEntryPoint());
                break;
            }
        }
    }
    
    private boolean hasLuaPatterns(Function func) {
        // Check if function body references Lua-like patterns
        // This is a heuristic check
        try {
            AddressSetView body = func.getBody();
            InstructionIterator instIter = currentProgram.getListing().getInstructions(body, true);
            
            int suspiciousPatterns = 0;
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                String mnemonic = inst.getMnemonicString();
                
                // Look for typical Lua stack manipulation patterns
                // Lua uses offsets like [rcx+8], [rcx+16] for stack access
                String repr = inst.toString();
                if (repr.contains("+0x8]") || repr.contains("+0x10]") || 
                    repr.contains("+0x18]") || repr.contains("+0x20]")) {
                    suspiciousPatterns++;
                }
                
                if (suspiciousPatterns > 5) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return false;
    }
}
