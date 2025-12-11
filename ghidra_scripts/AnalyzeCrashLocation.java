//Analyze the crash location RIP=140d76dd3 and lua_setfield calling convention
//@category COA
//@author COA Script Extender

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.*;
import java.io.*;

public class AnalyzeCrashLocation extends GhidraScript {

    private PrintWriter out;

    @Override
    public void run() throws Exception {
        String userHome = System.getProperty("user.home");
        String outputPath = userHome + "/coa_script_extender/ghidra_output/crash_analysis.txt";
        new File(userHome + "/coa_script_extender/ghidra_output").mkdirs();
        out = new PrintWriter(new FileWriter(outputPath));
        
        println("=== Crash Location Analysis ===");
        out.println("=== Crash Location Analysis ===");
        out.println("Crash RIP: 0x140d76dd3");
        out.println();
        
        // The crash is at RIP=140d76dd3
        // lua_setfield is at 0x140D76D50 (base + 0xD76D50)
        // So crash is at offset 0xD76DD3 - 0xD76D50 = 0x83 = 131 bytes into lua_setfield
        
        long baseAddr = 0x140000000L;
        long crashRIP = 0x140d76dd3L;
        long setfieldStart = 0x140D76D50L;
        long offsetIntoCrash = crashRIP - setfieldStart;
        
        out.println("lua_setfield start: 0x" + Long.toHexString(setfieldStart));
        out.println("Crash location: 0x" + Long.toHexString(crashRIP));
        out.println("Offset into function: " + offsetIntoCrash + " bytes (0x" + Long.toHexString(offsetIntoCrash) + ")");
        out.println();
        
        // Analyze lua_setfield
        Address setfieldAddr = toAddr(setfieldStart);
        Function setfieldFunc = getFunctionAt(setfieldAddr);
        
        if (setfieldFunc == null) {
            // Try to find it by searching
            setfieldFunc = getFirstFunction();
            while (setfieldFunc != null) {
                if (setfieldFunc.getEntryPoint().getOffset() == setfieldStart) {
                    break;
                }
                setfieldFunc = getFunctionAfter(setfieldFunc);
            }
        }
        
        if (setfieldFunc != null) {
            out.println("=== lua_setfield Function ===");
            out.println("Name: " + setfieldFunc.getName());
            out.println("Entry: " + setfieldFunc.getEntryPoint());
            out.println("Signature: " + setfieldFunc.getSignature());
            out.println("Calling Convention: " + setfieldFunc.getCallingConventionName());
            out.println("Parameter Count: " + setfieldFunc.getParameterCount());
            
            for (Parameter param : setfieldFunc.getParameters()) {
                out.println("  Param: " + param.getName() + " : " + param.getDataType() + 
                           " @ " + param.getVariableStorage());
            }
            out.println();
            
            // Decompile to see internal logic
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(currentProgram);
            
            DecompileResults results = decomp.decompileFunction(setfieldFunc, 60, monitor);
            if (results.decompileCompleted()) {
                out.println("=== Decompiled lua_setfield ===");
                out.println(results.getDecompiledFunction().getC());
            }
            decomp.dispose();
            
            // Look at the crash instruction
            out.println();
            out.println("=== Instructions around crash (0x" + Long.toHexString(crashRIP) + ") ===");
            Address crashAddr = toAddr(crashRIP);
            
            // Get 10 instructions before and after crash
            Listing listing = currentProgram.getListing();
            Instruction inst = listing.getInstructionContaining(crashAddr);
            
            if (inst != null) {
                // Go back 10 instructions
                Instruction curr = inst;
                for (int i = 0; i < 10 && curr != null; i++) {
                    curr = curr.getPrevious();
                }
                
                // Now print forward 20 instructions
                if (curr == null) curr = inst;
                for (int i = 0; i < 20 && curr != null; i++) {
                    String marker = curr.getAddress().equals(crashAddr) ? " <-- CRASH HERE" : "";
                    out.println(String.format("  %s: %s%s", 
                        curr.getAddress(), curr.toString(), marker));
                    curr = curr.getNext();
                }
            }
        } else {
            out.println("ERROR: Could not find lua_setfield function at " + setfieldAddr);
        }
        
        out.println();
        out.println("=== Crash Analysis ===");
        out.println("RAX=0 RBX=0 means a NULL pointer is being dereferenced");
        out.println("Read at 0x00000018 means accessing offset 0x18 (24 bytes) into a NULL structure");
        out.println("This is likely accessing L->top or similar lua_State field through NULL");
        out.println();
        out.println("Possible causes:");
        out.println("1. lua_State* (L) is invalid/corrupted");
        out.println("2. Stack index (-1 or LUA_GLOBALSINDEX) is wrong for this Lua version");
        out.println("3. The string pointer for field name is invalid");
        out.println("4. Lua internal state is corrupted");
        
        // Also analyze lua_createtable and lua_setglobal for comparison
        analyzeFunction(0x140D69D40L, "lua_createtable");
        analyzeFunction(0x140D773F0L, "lua_setglobal");
        analyzeFunction(0x140D6FD10L, "lua_gettop");
        
        out.close();
        println("Analysis written to: " + outputPath);
    }
    
    private void analyzeFunction(long addr, String expectedName) {
        try {
            Address funcAddr = toAddr(addr);
            Function func = getFunctionAt(funcAddr);
            
            if (func == null) {
                func = currentProgram.getListing().getFunctionContaining(funcAddr);
            }
            
            out.println();
            out.println("=== " + expectedName + " (0x" + Long.toHexString(addr) + ") ===");
            
            if (func != null) {
                out.println("Actual name: " + func.getName());
                out.println("Signature: " + func.getSignature());
                out.println("Calling Conv: " + func.getCallingConventionName());
                
                // Decompile
                DecompInterface decomp = new DecompInterface();
                decomp.openProgram(currentProgram);
                DecompileResults results = decomp.decompileFunction(func, 60, monitor);
                if (results.decompileCompleted()) {
                    String code = results.getDecompiledFunction().getC();
                    // Just first 30 lines
                    String[] lines = code.split("\n");
                    for (int i = 0; i < Math.min(30, lines.length); i++) {
                        out.println(lines[i]);
                    }
                    if (lines.length > 30) {
                        out.println("... (" + (lines.length - 30) + " more lines)");
                    }
                }
                decomp.dispose();
            } else {
                out.println("Function not found!");
            }
        } catch (Exception e) {
            out.println("Error: " + e.getMessage());
        }
    }
}
