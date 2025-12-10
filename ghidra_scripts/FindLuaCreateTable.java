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

    // Known functions to exclude from candidates
    private static final long[] KNOWN_FUNCTIONS = {
        0x00D7B070,  // luaV_execute (huge function)
        0x00D77210,  // luaH_new itself
        0x00D77E80,  // luaH_resize
        0x00D71420,  // lua_resume
        0x00D6AB20,  // lua_pushcclosure
        0x00D6E580,  // luaL_setfuncs
    };

    @Override
    public void run() throws Exception {
        println("=== Finding lua_createtable ===");
        println("");
        
        // Known address of luaH_new from our analysis
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
        ReferenceIterator refIter = refMgr.getReferencesTo(luaHNewAddr);
        
        println("Functions that call luaH_new:");
        println("-".repeat(60));
        
        // Use LinkedHashMap to preserve order and eliminate duplicates
        LinkedHashMap<Address, FunctionCandidate> candidateMap = new LinkedHashMap<>();
        
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (!ref.getReferenceType().isCall()) continue;
            
            Function caller = getFunctionContaining(ref.getFromAddress());
            if (caller == null) continue;
            
            Address callerAddr = caller.getEntryPoint();
            
            // Skip if already processed
            if (candidateMap.containsKey(callerAddr)) continue;
            
            // Skip known functions
            long offset = callerAddr.getOffset() - 0x140000000L;
            if (isKnownFunction(offset)) {
                println(String.format("  0x%08X: %s [SKIPPED - known function]", offset, caller.getName()));
                continue;
            }
            
            long size = caller.getBody().getNumAddresses();
            
            // Skip very large functions (not lua_createtable)
            if (size > 500) {
                println(String.format("  0x%08X: %s [SKIPPED - too large: %d bytes]", offset, caller.getName(), size));
                continue;
            }
            
            // Analyze the caller
            FunctionAnalysis analysis = analyzeFunction(caller);
            
            println(String.format("  0x%08X: %s", offset, caller.getName()));
            println(String.format("    Size: %d bytes, Instructions: %d", size, analysis.instructionCount));
            println(String.format("    Score: %d/100 - %s", analysis.score, analysis.details));
            
            if (analysis.score >= 60) {
                println("    >>> LIKELY lua_createtable <<<");
                candidateMap.put(callerAddr, new FunctionCandidate(caller, analysis.score, size));
            } else if (analysis.score >= 40) {
                println("    >>> POSSIBLE lua_createtable <<<");
                candidateMap.put(callerAddr, new FunctionCandidate(caller, analysis.score, size));
            }
            println("");
        }
        
        // Sort candidates by score (highest first)
        List<Map.Entry<Address, FunctionCandidate>> sortedCandidates = 
            new ArrayList<>(candidateMap.entrySet());
        sortedCandidates.sort((a, b) -> Integer.compare(b.getValue().score, a.getValue().score));
        
        // Summary
        println("");
        println("=".repeat(60));
        println("BEST CANDIDATES FOR lua_createtable (sorted by score):");
        println("=".repeat(60));
        
        if (sortedCandidates.isEmpty()) {
            println("No candidates found.");
        } else {
            println("");
            println("RECOMMENDED: Use the FIRST entry (highest score + smallest size)");
            println("");
            
            for (Map.Entry<Address, FunctionCandidate> entry : sortedCandidates) {
                FunctionCandidate fc = entry.getValue();
                long off = fc.func.getEntryPoint().getOffset() - 0x140000000L;
                String confidence = fc.score >= 70 ? "HIGH" : fc.score >= 50 ? "MEDIUM" : "LOW";
                println(String.format("  0x%08X - %s (size: %d, score: %d, confidence: %s)", 
                    off, fc.func.getName(), fc.size, fc.score, confidence));
            }
            
            // Show best candidate
            if (!sortedCandidates.isEmpty()) {
                FunctionCandidate best = sortedCandidates.get(0).getValue();
                long bestOffset = best.func.getEntryPoint().getOffset() - 0x140000000L;
                
                println("");
                println("=".repeat(60));
                println("RECOMMENDED OFFSET FOR coa_lua_bridge.cpp:");
                println("=".repeat(60));
                println(String.format("#define LUA_CREATETABLE_OFFSET  0x%08X", bestOffset));
                println("");
                println("Function details:");
                println(String.format("  Address: 0x%08X", bestOffset));
                println(String.format("  Name: %s", best.func.getName()));
                println(String.format("  Size: %d bytes", best.size));
                println(String.format("  Score: %d/100", best.score));
            }
        }
        
        println("");
        println("=".repeat(60));
        println("VERIFICATION STEPS:");
        println("=".repeat(60));
        println("1. Go to the recommended address in Ghidra");
        println("2. Check decompiled code - should look like:");
        println("   void lua_createtable(lua_State *L, int narray, int nrec) {");
        println("       Table *t = luaH_new(L);");
        println("       sethvalue(L, L->top, t);  // writes to L->top");
        println("       api_incr_top(L);          // increments L->top by 0x10");
        println("       if (narray > 0 || nrec > 0)");
        println("           luaH_resize(L, t, narray, nrec);");
        println("   }");
        println("3. Verify it has 3 parameters (L, narray, nrec)");
        println("4. Verify it's ~100-150 bytes (small function)");
        println("");
    }
    
    private boolean isKnownFunction(long offset) {
        for (long known : KNOWN_FUNCTIONS) {
            if (known == offset) return true;
        }
        return false;
    }
    
    private FunctionAnalysis analyzeFunction(Function func) {
        FunctionAnalysis result = new FunctionAnalysis();
        long size = func.getBody().getNumAddresses();
        
        InstructionIterator instrs = currentProgram.getListing()
            .getInstructions(func.getBody(), true);
        
        while (instrs.hasNext()) {
            Instruction inst = instrs.next();
            result.instructionCount++;
            String repr = inst.toString().toUpperCase();
            String mnemonic = inst.getMnemonicString().toUpperCase();
            
            // Check for writing to L->top (offset +0x10 from first param)
            // In x64, first param is RCX, so we look for [RCX+0x10]
            if (repr.contains("[RCX+0X10]") || repr.contains("[RCX + 0X10]")) {
                result.writesToTop = true;
            }
            
            // Also check for register-indirect after loading L
            if (repr.contains("+0X10]") && (mnemonic.equals("MOV") || mnemonic.equals("LEA"))) {
                result.writesToTop = true;
            }
            
            // Check for incrementing top by 0x10 (sizeof TValue)
            if ((mnemonic.equals("ADD") || mnemonic.equals("LEA")) && repr.contains("0X10")) {
                result.incrementsTop = true;
            }
            
            // Check for writing table type tag (LUA_TTABLE = 5, with variant bits = 0x45 or 0x05)
            if (repr.contains("0X45") || repr.contains(",0X5,") || repr.contains("0X5]")) {
                result.writesTableType = true;
            }
            
            // Check for MOV with immediate 5
            if (mnemonic.equals("MOV") && (repr.contains(",5") || repr.contains(", 5"))) {
                result.writesTableType = true;
            }
        }
        
        // Calculate score
        if (result.writesToTop) { result.score += 25; result.details += "writes_to_top "; }
        if (result.incrementsTop) { result.score += 25; result.details += "increments_top "; }
        if (result.writesTableType) { result.score += 20; result.details += "writes_table_type "; }
        
        // Size scoring - lua_createtable should be small (80-150 bytes typically)
        if (size >= 80 && size <= 150) { 
            result.score += 20; 
            result.details += "ideal_size "; 
        } else if (size >= 50 && size <= 200) { 
            result.score += 10; 
            result.details += "good_size "; 
        }
        
        // Instruction count scoring
        if (result.instructionCount >= 20 && result.instructionCount <= 50) { 
            result.score += 10; 
            result.details += "good_inst_count "; 
        }
        
        return result;
    }
    
    private class FunctionAnalysis {
        int score = 0;
        int instructionCount = 0;
        boolean writesToTop = false;
        boolean incrementsTop = false;
        boolean writesTableType = false;
        String details = "";
    }
    
    private class FunctionCandidate {
        Function func;
        int score;
        long size;
        
        FunctionCandidate(Function f, int s, long sz) {
            func = f;
            score = s;
            size = sz;
        }
    }
}
