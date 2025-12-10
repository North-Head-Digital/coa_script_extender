//Find Lua 5.2 core API functions by analyzing the lua.start handler
//@author COA Script Extender
//@category COA.Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import java.util.*;

public class FindLuaAPIs extends GhidraScript {

    // Known offsets from previous analysis
    private static final long LUA_START_HANDLER = 0x004BA470;
    private static final long LUA_TYPE_NEARBY = 0x00D6F630;
    private static final long LUAL_ERROR_NEARBY = 0x00D6CCF0;
    
    // Lua 5.2 function patterns - these are in a specific order in the binary
    // The Lua core functions are typically close together
    
    @Override
    protected void run() throws Exception {
        println("=== Finding Lua 5.2 Core API Functions ===");
        println("");
        
        long baseAddr = 0x140000000L;
        
        // Key functions we need to find
        Map<String, Long> foundFunctions = new LinkedHashMap<>();
        
        // Start from the known lua_type nearby function and scan the region
        println("Scanning Lua core region (0x00D6C000 - 0x00D90000)...");
        println("----------------------------------------");
        
        // These are approximate - Lua functions are typically grouped together
        // Based on the error messages found, these functions are in this region
        
        // Look for specific patterns
        Address luaRegionStart = toAddr(baseAddr + 0x00D6C000);
        Address luaRegionEnd = toAddr(baseAddr + 0x00D90000);
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcIter = funcMgr.getFunctions(luaRegionStart, true);
        
        List<Function> luaFunctions = new ArrayList<>();
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            if (func.getEntryPoint().compareTo(luaRegionEnd) > 0) break;
            luaFunctions.add(func);
        }
        
        println(String.format("Found %d functions in Lua region", luaFunctions.size()));
        println("");
        
        // Analyze each function to identify Lua APIs
        for (Function func : luaFunctions) {
            String funcType = identifyLuaFunction(func);
            if (funcType != null) {
                long offset = func.getEntryPoint().getOffset() - baseAddr;
                foundFunctions.put(funcType, offset);
                println(String.format("  %s = 0x%08X", funcType, offset));
            }
        }
        
        // Also scan for luaL_ library functions (usually after core lua_ functions)
        println("");
        println("Scanning for luaL_ auxiliary library functions...");
        println("----------------------------------------");
        
        // Search for specific strings that identify functions
        findFunctionByString("luaL_newstate", "bad seed", foundFunctions, baseAddr);
        findFunctionByString("lua_newstate", "cannot create state", foundFunctions, baseAddr);
        findFunctionByString("luaL_loadfile", "cannot %s %s", foundFunctions, baseAddr);
        findFunctionByString("luaL_loadbuffer", "too many arguments", foundFunctions, baseAddr);
        findFunctionByString("lua_pcall", "attempt to yield", foundFunctions, baseAddr);
        findFunctionByString("lua_call", "attempt to yield", foundFunctions, baseAddr);
        findFunctionByString("lua_error", "error in error handling", foundFunctions, baseAddr);
        findFunctionByString("luaL_ref", "reference index", foundFunctions, baseAddr);
        
        // Find lua_pushstring by looking for string handling
        findFunctionByString("lua_pushstring", "string length overflow", foundFunctions, baseAddr);
        
        // Output final results
        println("");
        println("========================================");
        println("COPY THESE TO coa_lua_bridge.cpp");
        println("========================================");
        println("");
        println("// Lua 5.2 function offsets (auto-discovered)");
        println("// Game: Call to Arms - Gates of Hell");
        println("");
        
        for (Map.Entry<String, Long> entry : foundFunctions.entrySet()) {
            println(String.format("#define LUA_%s_OFFSET  0x%08X", 
                entry.getKey().toUpperCase().replace("LUA", "").replace("_", ""), 
                entry.getValue()));
        }
        
        println("");
        println("// In ResolveLuaFunctions(), resolve like this:");
        println("// p_lua_pushstring = (lua_pushstring_t)COA_RVA(LUA_PUSHSTRING_OFFSET);");
        
        // Now specifically look for the lua.start handler to understand how Lua is initialized
        println("");
        println("========================================");
        println("ANALYZING lua.start HANDLER");
        println("========================================");
        println("");
        
        Address luaStartAddr = toAddr(baseAddr + LUA_START_HANDLER);
        Function luaStartFunc = getFunctionAt(luaStartAddr);
        
        if (luaStartFunc != null) {
            println(String.format("lua.start handler: %s", luaStartFunc.getName()));
            println(String.format("Address: 0x%s", luaStartAddr.toString()));
            
            // Find what functions it calls - one of them is likely luaL_newstate
            Reference[] refs = getReferencesFrom(luaStartFunc.getEntryPoint());
            Set<Address> calledFuncs = new HashSet<>();
            
            // Scan the function body for CALL instructions
            AddressSetView body = luaStartFunc.getBody();
            InstructionIterator instIter = currentProgram.getListing().getInstructions(body, true);
            
            println("");
            println("Functions called from lua.start handler:");
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                if (inst.getMnemonicString().equals("CALL")) {
                    Reference[] callRefs = inst.getReferencesFrom();
                    for (Reference ref : callRefs) {
                        Address target = ref.getToAddress();
                        if (!calledFuncs.contains(target)) {
                            calledFuncs.add(target);
                            Function targetFunc = getFunctionAt(target);
                            String name = targetFunc != null ? targetFunc.getName() : "unknown";
                            long offset = target.getOffset() - baseAddr;
                            println(String.format("  -> 0x%08X (%s)", offset, name));
                        }
                    }
                }
            }
        }
        
        println("");
        println("=== Analysis Complete ===");
        println("");
        println("RECOMMENDATION:");
        println("Hook the lua.start handler (0x004BA470) to capture the lua_State*");
        println("when it's created. Then call RegisterFunctions(L) to inject");
        println("the COA_Extender table into Lua.");
    }
    
    private String identifyLuaFunction(Function func) {
        // Analyze the function to identify its purpose
        // This is heuristic-based
        
        try {
            AddressSetView body = func.getBody();
            InstructionIterator instIter = currentProgram.getListing().getInstructions(body, true);
            
            int instCount = 0;
            boolean hasStackAccess = false;
            boolean returnsInt = false;
            String firstStringRef = null;
            
            while (instIter.hasNext() && instCount < 50) {
                Instruction inst = instIter.next();
                instCount++;
                
                String repr = inst.toString();
                
                // Check for Lua stack patterns (accessing L->stack, L->top, etc.)
                if (repr.contains("[RCX + 0x") || repr.contains("[RDI + 0x")) {
                    hasStackAccess = true;
                }
                
                // Check for string references
                Reference[] refs = inst.getReferencesFrom();
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isData()) {
                        try {
                            Address target = ref.getToAddress();
                            byte[] bytes = new byte[30];
                            currentProgram.getMemory().getBytes(target, bytes);
                            String str = new String(bytes).split("\0")[0];
                            if (str.length() > 2 && str.length() < 50) {
                                if (firstStringRef == null) {
                                    firstStringRef = str;
                                }
                            }
                        } catch (Exception e) {}
                    }
                }
            }
            
            // Very small functions (< 10 instructions) are likely simple accessors
            // These could be lua_type, lua_gettop, etc.
            if (instCount < 10 && hasStackAccess) {
                // Could be lua_gettop, lua_type, lua_isnil, etc.
                return null; // Need more analysis
            }
            
        } catch (Exception e) {
            // Ignore
        }
        
        return null;
    }
    
    private void findFunctionByString(String funcName, String searchString, 
                                       Map<String, Long> results, long baseAddr) {
        try {
            byte[] bytes = searchString.getBytes();
            Address found = currentProgram.getMemory().findBytes(
                currentProgram.getMinAddress(),
                bytes,
                null,
                true,
                monitor
            );
            
            if (found != null) {
                Reference[] refs = getReferencesTo(found);
                for (Reference ref : refs) {
                    Function func = getFunctionContaining(ref.getFromAddress());
                    if (func != null) {
                        long offset = func.getEntryPoint().getOffset() - baseAddr;
                        results.put(funcName, offset);
                        println(String.format("  %s (via '%s') = 0x%08X", 
                            funcName, searchString, offset));
                        break;
                    }
                }
            }
        } catch (Exception e) {
            println("  Error searching for " + funcName + ": " + e.getMessage());
        }
    }
}
