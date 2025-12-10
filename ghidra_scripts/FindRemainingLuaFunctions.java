//Find remaining Lua API functions needed for COA_Extender
//@author COA Script Extender
//@category COA.Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.util.*;

public class FindRemainingLuaFunctions extends GhidraScript {

    private static final long BASE = 0x140000000L;
    
    // Already found:
    // lua_pushstring = 0x00D7AC60
    // lua_type = 0x00D6F630  
    // luaL_error = 0x00D6CCF0
    // lua_pcall = 0x00D712A0
    
    // Need to find:
    // lua_createtable, lua_setfield, lua_setglobal
    // lua_pushcclosure, lua_pushnumber, lua_pushinteger, lua_pushboolean
    // lua_tonumber, lua_tostring, lua_toboolean
    // lua_settop, lua_gettop

    @Override
    protected void run() throws Exception {
        println("=== Finding Remaining Lua API Functions ===");
        println("");
        
        Map<String, Long> found = new LinkedHashMap<>();
        
        // Search for specific error strings unique to each function
        
        // lua_settop - look for "index out of range"
        findByString("lua_settop", "index out of range", found);
        
        // lua_gettop - very small function, usually just returns L->top - L->stack
        // Look near lua_settop
        
        // lua_createtable - look for "table overflow"
        findByString("lua_createtable", "table overflow", found);
        
        // lua_setfield - uses lua_pushstring internally, look for field access patterns
        // Often near lua_getfield
        findByString("lua_setfield", "invalid key to", found);
        
        // lua_setglobal - calls lua_setfield with _G
        // Look for functions that reference the "_G" string
        findByString("lua_setglobal", "_G", found);
        findByString("lua_getglobal", "_G", found);
        
        // lua_pushcclosure - look for "too many upvalues"
        findByString("lua_pushcclosure", "too many upvalues", found);
        
        // lua_pushnumber - very simple, just pushes a number
        // lua_pushinteger - similar
        // lua_pushboolean - look for pushing true/false
        
        // lua_tonumber - look for "number expected" or check near lua_type
        findByString("lua_tonumber", "number expected", found);
        
        // lua_tolstring - look for "string expected"  
        findByString("lua_tolstring", "string expected", found);
        
        // luaL_newstate - look for "not enough memory" or "cannot create state"
        findByString("luaL_newstate", "cannot create state", found);
        findByString("lua_newstate", "not enough memory", found);
        
        // luaL_openlibs - calls multiple luaopen_ functions
        findByString("luaL_openlibs", "luaopen_", found);
        
        // lua_close - look for "gc", cleanup
        findByString("lua_close", "panic: ", found);
        
        println("");
        println("========================================");
        println("Analyzing Lua region functions...");
        println("========================================");
        
        // Functions in the 0x00D6xxxx-0x00D7xxxx range that are small
        // are likely simple Lua API functions
        
        Address start = toAddr(BASE + 0x00D68000);
        Address end = toAddr(BASE + 0x00D6A000);
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator iter = funcMgr.getFunctions(start, true);
        
        println("");
        println("Small functions (< 30 bytes) in early Lua region:");
        println("These are likely lua_gettop, lua_settop, lua_pushnil, etc.");
        println("");
        
        List<Function> smallFuncs = new ArrayList<>();
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getEntryPoint().compareTo(end) > 0) break;
            
            long size = func.getBody().getNumAddresses();
            if (size < 30) {
                smallFuncs.add(func);
                long offset = func.getEntryPoint().getOffset() - BASE;
                println(String.format("  0x%08X - %d bytes - %s", offset, size, func.getName()));
            }
        }
        
        // Analyze the candidates from lua.start
        println("");
        println("========================================");
        println("Analyzing lua.start called functions:");
        println("========================================");
        println("");
        
        long[] candidates = {
            0x00D6A9F0,  // First Lua-region call - likely luaL_newstate
            0x00D6BE50,  // Second - likely luaL_openlibs
            0x00D6C350,
            0x00D6A140,
            0x00D699A0,
            0x00D6A6E0,
            0x00D6B9B0
        };
        
        for (long offset : candidates) {
            Address addr = toAddr(BASE + offset);
            Function func = getFunctionAt(addr);
            if (func != null) {
                analyzeFunction(func, offset);
            }
        }
        
        // Output final results
        println("");
        println("========================================");
        println("ADD THESE TO coa_lua_bridge.cpp");
        println("========================================");
        println("");
        
        for (Map.Entry<String, Long> entry : found.entrySet()) {
            String name = entry.getKey().toUpperCase().replace("LUA", "").replace("_", "");
            println(String.format("#define LUA_%s_OFFSET  0x%08X", name, entry.getValue()));
        }
        
        println("");
        println("=== Complete ===");
    }
    
    private void findByString(String funcName, String searchStr, Map<String, Long> found) {
        try {
            byte[] bytes = searchStr.getBytes();
            Address strAddr = currentProgram.getMemory().findBytes(
                currentProgram.getMinAddress(), bytes, null, true, monitor);
            
            if (strAddr != null) {
                Reference[] refs = getReferencesTo(strAddr);
                for (Reference ref : refs) {
                    Function func = getFunctionContaining(ref.getFromAddress());
                    if (func != null) {
                        long offset = func.getEntryPoint().getOffset() - BASE;
                        // Only accept if in Lua region
                        if (offset >= 0x00D60000 && offset <= 0x00DA0000) {
                            found.put(funcName, offset);
                            println(String.format("  %s = 0x%08X (via '%s')", funcName, offset, searchStr));
                            break;
                        }
                    }
                }
            }
        } catch (Exception e) {}
    }
    
    private void analyzeFunction(Function func, long offset) {
        try {
            long size = func.getBody().getNumAddresses();
            
            // Check what strings are referenced
            Set<String> strRefs = new HashSet<>();
            AddressSetView body = func.getBody();
            InstructionIterator instIter = currentProgram.getListing().getInstructions(body, true);
            
            int callCount = 0;
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                
                if (inst.getMnemonicString().equals("CALL")) {
                    callCount++;
                }
                
                // Check for string references
                Reference[] refs = inst.getReferencesFrom();
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isData()) {
                        try {
                            Address target = ref.getToAddress();
                            byte[] bytes = new byte[40];
                            currentProgram.getMemory().getBytes(target, bytes);
                            String str = new String(bytes).split("\0")[0];
                            if (str.length() > 2 && str.length() < 40 && str.matches(".*[a-z].*")) {
                                strRefs.add(str);
                            }
                        } catch (Exception e) {}
                    }
                }
            }
            
            String guess = guessFunction(size, callCount, strRefs);
            
            println(String.format("0x%08X: size=%d, calls=%d, strings=%s", 
                offset, size, callCount, strRefs.toString()));
            if (guess != null) {
                println(String.format("  -> LIKELY: %s", guess));
            }
            println("");
            
        } catch (Exception e) {
            println(String.format("0x%08X: analysis error", offset));
        }
    }
    
    private String guessFunction(long size, int callCount, Set<String> strings) {
        // Heuristics to guess function identity
        
        if (strings.contains("cannot create state") || strings.contains("not enough memory")) {
            return "luaL_newstate / lua_newstate";
        }
        if (strings.contains("_G") || strings.contains("_VERSION")) {
            return "luaL_openlibs or global table setup";
        }
        if (callCount > 10 && size > 200) {
            return "luaL_openlibs (many library opens)";
        }
        if (size < 50 && callCount == 0) {
            return "Simple accessor (lua_gettop, lua_type, etc.)";
        }
        
        return null;
    }
}
