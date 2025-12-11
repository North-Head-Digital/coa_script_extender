//Find the real public Lua API wrappers that convert stack indices to internal calls
//@category COA
//@author COA Script Extender

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class FindRealLuaAPI extends GhidraScript {

    private PrintWriter out;
    private DecompInterface decomp;
    
    // Known internal functions (from crash analysis)
    private static final long INTERNAL_SETFIELD = 0x140d76d50L;  // Takes 4 params, internal
    private static final long INTERNAL_NEXT = 0x140d777b0L;      // Called by setfield
    
    @Override
    public void run() throws Exception {
        String userHome = System.getProperty("user.home");
        String outputPath = userHome + "/coa_script_extender/ghidra_output/real_lua_api.txt";
        new File(userHome + "/coa_script_extender/ghidra_output").mkdirs();
        out = new PrintWriter(new FileWriter(outputPath));
        
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        println("=== Finding Real Lua Public API ===");
        out.println("=== Finding Real Lua Public API ===");
        out.println();
        out.println("The crash analysis shows that 0x140d76d50 is an INTERNAL function");
        out.println("that takes (L, table_ptr, key_tvalue, value_tvalue) not stack indices.");
        out.println();
        out.println("We need to find wrapper functions that:");
        out.println("1. Take (lua_State*, int idx, const char* name)");
        out.println("2. Convert stack index to actual table pointer");
        out.println("3. Call the internal function");
        out.println();
        
        // Find all functions that call the internal setfield
        out.println("=== Functions that call internal setfield (0x140d76d50) ===");
        findCallersOf(INTERNAL_SETFIELD, "internal_setfield");
        
        // Also find callers of lua_setglobal since it wraps setfield
        out.println();
        out.println("=== Functions that call lua_setglobal wrapper (0x140d773f0) ===");
        findCallersOf(0x140d773f0L, "lua_setglobal");
        
        // Look for the index-to-pointer conversion function
        // Standard Lua uses something like index2addr or index2adr
        out.println();
        out.println("=== Searching for index2addr / stack index conversion ===");
        findIndexConverter();
        
        // Look for the REAL lua_setfield that takes 3 params (L, idx, name)
        out.println();
        out.println("=== Searching for 3-param setfield wrapper ===");
        findThreeParamSetfield();
        
        // Analyze lua_rawset and lua_settable as alternatives
        out.println();
        out.println("=== Alternative: lua_rawset / lua_settable ===");
        findAlternativeSetters();
        
        decomp.dispose();
        out.close();
        println("Analysis written to: " + outputPath);
    }
    
    private void findCallersOf(long targetAddr, String name) {
        Address target = toAddr(targetAddr);
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        
        ReferenceIterator refs = refMgr.getReferencesTo(target);
        int count = 0;
        
        while (refs.hasNext() && count < 20) {
            Reference ref = refs.next();
            if (ref.getReferenceType().isCall()) {
                Address from = ref.getFromAddress();
                Function caller = getFunctionContaining(from);
                if (caller != null) {
                    out.println();
                    out.println("Caller: " + caller.getName() + " at " + caller.getEntryPoint());
                    out.println("  Signature: " + caller.getSignature());
                    out.println("  Param count: " + caller.getParameterCount());
                    
                    // Decompile to see if it handles stack indices
                    DecompileResults results = decomp.decompileFunction(caller, 30, monitor);
                    if (results.decompileCompleted()) {
                        String code = results.getDecompiledFunction().getC();
                        // Look for signs of index handling
                        if (code.contains("index") || code.contains("idx") || 
                            code.contains("0x10") || code.contains("+ 0x10")) {
                            out.println("  [LIKELY] Contains index/offset operations");
                        }
                        // Print first 25 lines
                        String[] lines = code.split("\n");
                        for (int i = 0; i < Math.min(25, lines.length); i++) {
                            out.println("  " + lines[i]);
                        }
                    }
                    count++;
                }
            }
        }
        out.println("Found " + count + " callers");
    }
    
    private void findIndexConverter() {
        // Look for small functions that convert stack index to pointer
        // Pattern: take (L, idx), return pointer from L's stack
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcs = funcMgr.getFunctions(true);
        
        int candidates = 0;
        while (funcs.hasNext() && candidates < 10) {
            Function func = funcs.next();
            
            // Look for small functions with 2 params returning a pointer
            if (func.getParameterCount() == 2) {
                long size = func.getBody().getNumAddresses();
                if (size > 10 && size < 100) {
                    DecompileResults results = decomp.decompileFunction(func, 30, monitor);
                    if (results.decompileCompleted()) {
                        String code = results.getDecompiledFunction().getC();
                        // Look for stack index patterns: negative index, param_1 + 0x10, etc.
                        if ((code.contains("< 0") || code.contains("<= 0") || code.contains("< 1")) &&
                            (code.contains("+ 0x10") || code.contains("param_1 + "))) {
                            out.println();
                            out.println("CANDIDATE index2addr: " + func.getName() + " at " + func.getEntryPoint());
                            out.println("  Size: " + size + " bytes");
                            String[] lines = code.split("\n");
                            for (int i = 0; i < Math.min(20, lines.length); i++) {
                                out.println("  " + lines[i]);
                            }
                            candidates++;
                        }
                    }
                }
            }
        }
    }
    
    private void findThreeParamSetfield() {
        // Standard lua_setfield signature: void lua_setfield(lua_State*, int, const char*)
        // Look for functions that:
        // 1. Take 3 parameters
        // 2. Call the internal 4-param setfield
        
        Address internalSetfield = toAddr(INTERNAL_SETFIELD);
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        
        ReferenceIterator refs = refMgr.getReferencesTo(internalSetfield);
        
        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (ref.getReferenceType().isCall()) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null && caller.getParameterCount() == 3) {
                    out.println();
                    out.println("*** 3-PARAM WRAPPER FOUND ***");
                    out.println("Function: " + caller.getName() + " at " + caller.getEntryPoint());
                    out.println("Signature: " + caller.getSignature());
                    
                    DecompileResults results = decomp.decompileFunction(caller, 30, monitor);
                    if (results.decompileCompleted()) {
                        out.println(results.getDecompiledFunction().getC());
                    }
                }
            }
        }
    }
    
    private void findAlternativeSetters() {
        // Look for lua_rawset, lua_settable, lua_rawseti patterns
        // These might be simpler to use
        
        // lua_rawseti pattern: takes (L, idx, n) and does table[n] = value
        // Look for functions that access table array part directly
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcs = funcMgr.getFunctions(true);
        
        List<String> keywords = Arrays.asList("rawset", "settable", "rawseti");
        
        while (funcs.hasNext()) {
            Function func = funcs.next();
            String name = func.getName().toLowerCase();
            
            for (String kw : keywords) {
                if (name.contains(kw)) {
                    out.println();
                    out.println("Found: " + func.getName() + " at " + func.getEntryPoint());
                    out.println("Signature: " + func.getSignature());
                    
                    DecompileResults results = decomp.decompileFunction(func, 30, monitor);
                    if (results.decompileCompleted()) {
                        String[] lines = results.getDecompiledFunction().getC().split("\n");
                        for (int i = 0; i < Math.min(30, lines.length); i++) {
                            out.println(lines[i]);
                        }
                    }
                }
            }
        }
        
        // Also check for the luaL_setfuncs we found earlier
        out.println();
        out.println("=== luaL_setfuncs (0x140D6E580) ===");
        analyzeFunction(0x140D6E580L);
    }
    
    private void analyzeFunction(long addr) {
        Function func = getFunctionAt(toAddr(addr));
        if (func == null) {
            func = getFunctionContaining(toAddr(addr));
        }
        
        if (func != null) {
            out.println("Function: " + func.getName() + " at " + func.getEntryPoint());
            out.println("Signature: " + func.getSignature());
            out.println("Params: " + func.getParameterCount());
            
            DecompileResults results = decomp.decompileFunction(func, 60, monitor);
            if (results.decompileCompleted()) {
                out.println(results.getDecompiledFunction().getC());
            }
        } else {
            out.println("Function not found at " + Long.toHexString(addr));
        }
    }
}
