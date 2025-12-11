//Find lua_setglobal - the 2-parameter wrapper that sets a global variable
//@category COA
//@author COA Script Extender

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class FindLuaSetGlobalReal extends GhidraScript {

    private PrintWriter out;
    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String userHome = System.getProperty("user.home");
        String outputPath = userHome + "/coa_script_extender/ghidra_output/lua_setglobal_real.txt";
        new File(userHome + "/coa_script_extender/ghidra_output").mkdirs();
        out = new PrintWriter(new FileWriter(outputPath));
        
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        println("=== Finding Real lua_setglobal ===");
        out.println("=== Finding Real lua_setglobal ===");
        out.println();
        out.println("lua_setglobal(L, name) should:");
        out.println("1. Take 2 params: lua_State* L, const char* name");
        out.println("2. Pop the top value from stack");
        out.println("3. Set it as _G[name]");
        out.println();
        out.println("Looking for 2-param functions in Lua code range...");
        out.println();
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcs = funcMgr.getFunctions(true);
        
        int candidates = 0;
        while (funcs.hasNext() && candidates < 30) {
            Function func = funcs.next();
            long entry = func.getEntryPoint().getOffset();
            
            // Only look in Lua code range
            if (entry < 0x140d60000L || entry > 0x140d90000L) continue;
            
            // lua_setglobal should take exactly 2 params
            if (func.getParameterCount() != 2) continue;
            
            // Check the decompilation for signs of setglobal behavior
            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            if (!results.decompileCompleted()) continue;
            
            String code = results.getDecompiledFunction().getC();
            
            // lua_setglobal typically:
            // - Accesses the globals table (often at L->l_G or via registry)
            // - Calls lua_setfield with LUA_GLOBALSINDEX or similar
            // - Has a string parameter (the global name)
            // - Decrements stack top (pops value)
            
            // Look for patterns suggesting setglobal
            boolean hasStringParam = func.getSignature().toString().contains("char *") ||
                                    code.contains("param_2");
            boolean accessesGlobals = code.contains("0x40") || code.contains("+ 0x28") ||
                                     code.contains("_G") || code.contains("global");
            boolean modifiesStack = code.contains("+ 0x10") || code.contains("- 0x10") ||
                                   code.contains("param_1 + ");
            
            // Strong candidate if it calls lua_setfield (0xd6b670)
            boolean callsSetfield = code.contains("d6b670") || code.contains("FUN_140d6b670");
            
            if (hasStringParam && (accessesGlobals || callsSetfield || modifiesStack)) {
                out.println();
                out.println("=== CANDIDATE: " + func.getName() + " at " + func.getEntryPoint() + " ===");
                out.println("Params: " + func.getParameterCount());
                out.println("Signature: " + func.getSignature());
                if (callsSetfield) out.println("  ** Calls lua_setfield! **");
                
                String[] lines = code.split("\n");
                for (int i = 0; i < Math.min(35, lines.length); i++) {
                    out.println(lines[i]);
                }
                candidates++;
            }
        }
        
        // Also specifically analyze the function that was wrongly identified
        out.println();
        out.println("=== Analyzing wrongly-identified 0x140d773f0 ===");
        Function wrongFunc = getFunctionAt(toAddr(0x140d773f0L));
        if (wrongFunc != null) {
            out.println("This is: " + wrongFunc.getName());
            out.println("Params: " + wrongFunc.getParameterCount());
            out.println("Signature: " + wrongFunc.getSignature());
            out.println("This is NOT lua_setglobal - it takes 4 params!");
        }
        
        // Look at what calls the real lua_setfield (0x140d6b670)
        out.println();
        out.println("=== Who calls real lua_setfield (0x140d6b670)? ===");
        Address setfieldAddr = toAddr(0x140d6b670L);
        ghidra.program.model.symbol.ReferenceManager refMgr = currentProgram.getReferenceManager();
        ghidra.program.model.symbol.ReferenceIterator refs = refMgr.getReferencesTo(setfieldAddr);
        
        int count = 0;
        while (refs.hasNext() && count < 20) {
            ghidra.program.model.symbol.Reference ref = refs.next();
            if (ref.getReferenceType().isCall()) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null && caller.getParameterCount() == 2) {
                    out.println();
                    out.println("*** 2-PARAM caller: " + caller.getName() + " at " + caller.getEntryPoint() + " ***");
                    DecompileResults results = decomp.decompileFunction(caller, 30, monitor);
                    if (results.decompileCompleted()) {
                        String[] lines = results.getDecompiledFunction().getC().split("\n");
                        for (int i = 0; i < Math.min(25, lines.length); i++) {
                            out.println(lines[i]);
                        }
                    }
                }
                count++;
            }
        }
        
        decomp.dispose();
        out.close();
        println("Analysis written to: " + outputPath);
    }
}
