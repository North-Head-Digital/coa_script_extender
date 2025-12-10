//Find lua_createtable by tracing from luaH_new
//@author COA Script Extender Team  
//@category Lua
//@keybinding
//@menupath Analysis.Find lua_createtable
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.util.*;

public class FindLuaCreateTable extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== Finding lua_createtable ===");
        println("");
        
        // Known address of luaH_new from our analysis
        // luaH_new creates the table object but doesn't push to stack
        Address luaHNewAddr = toAddr(0x140d77210L);
        
        Function luaHNew = getFunctionAt(luaHNewAddr);
        if (luaHNew == null) {
            println("ERROR: luaH_new not found at expected address 0x140d77210");
            println("Please verify this address in your binary");
            return;
        }
        
        println("Found luaH_new at: " + luaHNewAddr);
        println("");
        
        // Find all callers of luaH_new
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Reference[] refs = refMgr.getReferencesTo(luaHNewAddr);
        
        println("Functions that call luaH_new:");
        println("-".repeat(60));
        
        List<Function> candidates = new ArrayList<>();
        
        for (Reference ref : refs) {
            if (!ref.getReferenceType().isCall()) continue;
            
            Function caller = getFunctionContaining(ref.getFromAddress());
            if (caller == null) continue;
            
            Address callerAddr = caller.getEntryPoint();
            long size = caller.getBody().getNumAddresses();
            
            // Analyze the caller
            boolean writesToTop = false;
            boolean incrementsTop = false;
            boolean writesTableType = false;
            int instructionCount = 0;
            
            InstructionIterator instrs = currentProgram.getListing()
                .getInstructions(caller.getBody(), true);
            
            while (instrs.hasNext()) {
                Instruction inst = instrs.next();
                instructionCount++;
                String repr = inst.toString();
                
                // Check for writing to L->top (offset +0x10)
                if (repr.contains("[") && repr.contains("+0x10]")) {
                    writesToTop = true;
                }
                
                // Check for incrementing top by 0x10 (sizeof TValue)
                if (repr.contains("0x10") && 
                    (repr.contains("ADD") || repr.contains("LEA"))) {
                    incrementsTop = true;
                }
                
                // Check for writing table type (0x45 or 0x05 or 5)
                if (repr.contains("0x45") || repr.contains(",0x5,") || 
                    repr.contains(",5]") || repr.contains("= 0x45")) {
                    writesTableType = true;
                }
            }
            
            // Score the candidate
            int score = 0;
            String analysis = "";
            
            if (writesToTop) { score += 30; analysis += "writes_to_top "; }
            if (incrementsTop) { score += 30; analysis += "increments_top "; }
            if (writesTableType) { score += 20; analysis += "writes_table_type "; }
            if (size >= 50 && size <= 200) { score += 20; analysis += "good_size "; }
            if (instructionCount >= 15 && instructionCount <= 60) { 
                score += 10; 
                analysis += "good_inst_count "; 
            }
            
            println(String.format("  0x%s: %s", callerAddr, caller.getName()));
            println(String.format("    Size: %d bytes, Instructions: %d", size, instructionCount));
            println(String.format("    Score: %d/100 - %s", score, analysis));
            
            if (score >= 50) {
                println("    >>> HIGH PROBABILITY lua_createtable <<<");
                candidates.add(caller);
            }
            println("");
        }
        
        // Summary
        println("");
        println("=".repeat(60));
        println("BEST CANDIDATES FOR lua_createtable:");
        println("=".repeat(60));
        
        if (candidates.isEmpty()) {
            println("No strong candidates found.");
            println("Try examining the functions above manually.");
        } else {
            for (Function f : candidates) {
                long offset = f.getEntryPoint().getOffset() - 0x140000000L;
                println(String.format("  0x%08X - %s (size: %d bytes)", 
                    offset, f.getName(), f.getBody().getNumAddresses()));
            }
            
            println("");
            println("To use in coa_lua_bridge.cpp:");
            for (Function f : candidates) {
                long offset = f.getEntryPoint().getOffset() - 0x140000000L;
                println(String.format("#define LUA_CREATETABLE_OFFSET  0x%08X", offset));
            }
        }
        
        println("");
        println("=".repeat(60));
        println("VERIFICATION STEPS:");
        println("=".repeat(60));
        println("1. Double-click candidate function to view decompiled code");
        println("2. Verify it has signature: void(lua_State*, int, int)");
        println("3. Verify it calls luaH_new at 0x140d77210");
        println("4. Verify it writes to offset +0x10 (L->top)");
        println("5. Verify it increments L->top by 0x10");
        println("");
    }
}
