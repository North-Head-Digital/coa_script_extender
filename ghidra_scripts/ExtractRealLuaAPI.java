//Extract the REAL Lua API addresses from luaL_setfuncs
//@category COA
//@author COA Script Extender

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class ExtractRealLuaAPI extends GhidraScript {

    private PrintWriter out;
    private DecompInterface decomp;
    private Map<Long, String> identifiedFuncs = new HashMap<>();

    @Override
    public void run() throws Exception {
        String userHome = System.getProperty("user.home");
        String outputPath = userHome + "/coa_script_extender/ghidra_output/real_lua_offsets.txt";
        new File(userHome + "/coa_script_extender/ghidra_output").mkdirs();
        out = new PrintWriter(new FileWriter(outputPath));
        
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        println("=== Extracting Real Lua API Addresses ===");
        out.println("=== REAL Lua API Offsets ===");
        out.println("Base address: 0x140000000");
        out.println();
        
        // From luaL_setfuncs analysis, we can identify:
        // FUN_140d6ab20 = lua_pushcclosure (confirmed - we already had this)
        // FUN_140d6b670 = lua_setfield (sets table[-2-nup] with name from param)
        // FUN_140d6b9b0 = lua_settop or lua_pop
        // FUN_140d6d330 = some string/check function
        // FUN_140d6adf0 = lua_pushvalue (copies value at index)
        // FUN_140d69a20 = luaL_checkstack
        
        identifiedFuncs.put(0x140d6ab20L, "lua_pushcclosure");
        identifiedFuncs.put(0x140d6b670L, "lua_setfield (REAL)");
        identifiedFuncs.put(0x140d6b9b0L, "lua_settop/pop");
        identifiedFuncs.put(0x140d6adf0L, "lua_pushvalue");
        identifiedFuncs.put(0x140d69a20L, "luaL_checkstack");
        identifiedFuncs.put(0x140d6e580L, "luaL_setfuncs");
        
        // Analyze each function
        for (Map.Entry<Long, String> entry : identifiedFuncs.entrySet()) {
            analyzeFunction(entry.getKey(), entry.getValue());
        }
        
        // Now find lua_setglobal - it should call lua_setfield with a special index
        out.println();
        out.println("=== Finding lua_setglobal ===");
        findSetGlobal();
        
        // Find lua_createtable - verify our offset
        out.println();
        out.println("=== Verifying lua_createtable ===");
        analyzeFunction(0x140d69d40L, "lua_createtable (current)");
        
        // Find the index conversion function used by lua_setfield
        out.println();
        out.println("=== Analyzing lua_setfield (0x140d6b670) in detail ===");
        detailedAnalysis(0x140d6b670L);
        
        // Find callers of lua_setglobal to verify
        out.println();
        out.println("=== Functions that set globals ===");
        findGlobalSetters();
        
        // Summary
        out.println();
        out.println("=== SUMMARY: Correct Offsets ===");
        out.println("(Subtract 0x140000000 for relative offset)");
        out.println();
        out.println("lua_pushcclosure  = 0x00D6AB20  (0x140d6ab20) - VERIFIED");
        out.println("lua_setfield      = 0x00D6B670  (0x140d6b670) - NEW!");
        out.println("lua_createtable   = 0x00D69D40  (0x140d69d40) - needs verify");
        out.println("lua_settop        = 0x00D6B9B0  (0x140d6b9b0) - from setfuncs");
        out.println("lua_pushvalue     = 0x00D6ADF0  (0x140d6adf0) - from setfuncs");
        out.println("luaL_setfuncs     = 0x00D6E580  (0x140d6e580) - VERIFIED");
        
        decomp.dispose();
        out.close();
        println("Analysis written to: " + outputPath);
    }
    
    private void analyzeFunction(long addr, String name) {
        out.println();
        out.println("=== " + name + " (0x" + Long.toHexString(addr) + ") ===");
        
        Function func = getFunctionAt(toAddr(addr));
        if (func == null) {
            func = getFunctionContaining(toAddr(addr));
        }
        
        if (func != null) {
            out.println("Entry: " + func.getEntryPoint());
            out.println("Signature: " + func.getSignature());
            out.println("Params: " + func.getParameterCount());
            
            DecompileResults results = decomp.decompileFunction(func, 60, monitor);
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                for (int i = 0; i < Math.min(35, lines.length); i++) {
                    out.println(lines[i]);
                }
                if (lines.length > 35) {
                    out.println("... (" + (lines.length - 35) + " more lines)");
                }
            }
        } else {
            out.println("NOT FOUND!");
        }
    }
    
    private void detailedAnalysis(long addr) {
        Function func = getFunctionAt(toAddr(addr));
        if (func == null) return;
        
        DecompileResults results = decomp.decompileFunction(func, 120, monitor);
        if (results.decompileCompleted()) {
            out.println("Full decompilation:");
            out.println(results.getDecompiledFunction().getC());
        }
    }
    
    private void findSetGlobal() {
        // lua_setglobal typically uses LUA_GLOBALSINDEX or _G
        // Look for functions that call lua_setfield with a special index
        
        Address setfieldAddr = toAddr(0x140d6b670L);
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        ReferenceIterator refs = refMgr.getReferencesTo(setfieldAddr);
        
        int count = 0;
        while (refs.hasNext() && count < 10) {
            ghidra.program.model.symbol.Reference ref = refs.next();
            if (ref.getReferenceType().isCall()) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    out.println();
                    out.println("Caller of setfield: " + caller.getName() + " at " + caller.getEntryPoint());
                    out.println("  Params: " + caller.getParameterCount());
                    
                    // Check if it's a 2-param function (L, name) - that's setglobal
                    if (caller.getParameterCount() == 2) {
                        out.println("  *** LIKELY lua_setglobal ***");
                    }
                    
                    DecompileResults results = decomp.decompileFunction(caller, 30, monitor);
                    if (results.decompileCompleted()) {
                        String[] lines = results.getDecompiledFunction().getC().split("\n");
                        for (int i = 0; i < Math.min(20, lines.length); i++) {
                            out.println("  " + lines[i]);
                        }
                    }
                    count++;
                }
            }
        }
    }
    
    private void findGlobalSetters() {
        // Look for patterns that access _G or globals table
        // The global table index in Lua 5.2 is usually accessed via registry
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcs = funcMgr.getFunctions(true);
        
        int candidates = 0;
        while (funcs.hasNext() && candidates < 5) {
            Function func = funcs.next();
            
            // 2-param functions in the Lua range
            long entry = func.getEntryPoint().getOffset();
            if (entry >= 0x140d60000L && entry <= 0x140d90000L && 
                func.getParameterCount() == 2) {
                
                DecompileResults results = decomp.decompileFunction(func, 30, monitor);
                if (results.decompileCompleted()) {
                    String code = results.getDecompiledFunction().getC();
                    // Look for setfield call with registry/globals access
                    if (code.contains("0xd6b670") || code.contains("setfield") ||
                        (code.contains("0x40") && code.contains("FUN_140d6"))) {
                        out.println();
                        out.println("Candidate setglobal: " + func.getName() + " at " + func.getEntryPoint());
                        String[] lines = code.split("\n");
                        for (int i = 0; i < Math.min(15, lines.length); i++) {
                            out.println("  " + lines[i]);
                        }
                        candidates++;
                    }
                }
            }
        }
    }
}
