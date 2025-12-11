//Deep analysis of luaL_setfuncs - this is the RIGHT way to register functions
//@category COA
//@author COA Script Extender

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class AnalyzeLuaLSetfuncs extends GhidraScript {

    @Override
    public void run() throws Exception {
        String userHome = System.getProperty("user.home");
        String outputPath = userHome + "/coa_script_extender/ghidra_output/lual_setfuncs_analysis.txt";
        new File(userHome + "/coa_script_extender/ghidra_output").mkdirs();
        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        println("=== Analyzing luaL_setfuncs ===");
        out.println("=== luaL_setfuncs Deep Analysis ===");
        out.println();
        out.println("luaL_setfuncs is the STANDARD way to register a table of functions.");
        out.println("It takes: (L, luaL_Reg* funcs, int nup)");
        out.println("Where luaL_Reg is: { const char* name; lua_CFunction func; }");
        out.println();
        
        // Analyze luaL_setfuncs at 0x140D6E580
        long setfuncsAddr = 0x140D6E580L;
        Function func = getFunctionAt(toAddr(setfuncsAddr));
        if (func == null) {
            func = getFunctionContaining(toAddr(setfuncsAddr));
        }
        
        if (func != null) {
            out.println("Address: " + func.getEntryPoint());
            out.println("Name: " + func.getName());
            out.println("Signature: " + func.getSignature());
            out.println("Param count: " + func.getParameterCount());
            out.println();
            
            // Full decompile
            DecompileResults results = decomp.decompileFunction(func, 120, monitor);
            if (results.decompileCompleted()) {
                out.println("=== Full Decompilation ===");
                out.println(results.getDecompiledFunction().getC());
            }
            
            // Also analyze what functions it calls
            out.println();
            out.println("=== Functions called by luaL_setfuncs ===");
            
            Listing listing = currentProgram.getListing();
            InstructionIterator instIter = listing.getInstructions(func.getBody(), true);
            
            java.util.Set<Long> calledAddrs = new java.util.HashSet<>();
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                if (inst.getMnemonicString().equals("CALL")) {
                    Address target = inst.getAddress(0);
                    if (target != null) {
                        calledAddrs.add(target.getOffset());
                    }
                    // Also check reference
                    Reference[] refs = inst.getReferencesFrom();
                    for (Reference ref : refs) {
                        if (ref.getReferenceType().isCall()) {
                            calledAddrs.add(ref.getToAddress().getOffset());
                        }
                    }
                }
            }
            
            for (Long addr : calledAddrs) {
                Function callee = getFunctionAt(toAddr(addr));
                if (callee != null) {
                    out.println();
                    out.println("Calls: " + callee.getName() + " at 0x" + Long.toHexString(addr));
                    out.println("  Signature: " + callee.getSignature());
                }
            }
        } else {
            out.println("ERROR: Could not find function at 0x" + Long.toHexString(setfuncsAddr));
        }
        
        // Also look for luaL_register or luaL_openlib - older API
        out.println();
        out.println("=== Looking for luaL_register / luaL_openlib ===");
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcs = funcMgr.getFunctions(true);
        
        while (funcs.hasNext()) {
            Function f = funcs.next();
            String name = f.getName().toLowerCase();
            if (name.contains("register") || name.contains("openlib") || name.contains("newlib")) {
                out.println();
                out.println("Found: " + f.getName() + " at " + f.getEntryPoint());
                out.println("  Signature: " + f.getSignature());
            }
        }
        
        decomp.dispose();
        out.close();
        println("Analysis written to: " + outputPath);
    }
}
