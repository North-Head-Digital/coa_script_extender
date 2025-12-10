//Analyze the game's Lua initialization caller
//@category COA
//@author COA Script Extender

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;

public class AnalyzeLuaInitCaller extends GhidraScript {
    
    private long BASE = 0x140000000L;
    
    @Override
    public void run() throws Exception {
        println("=== Analyzing Game's Lua Initialization ===\n");
        
        // The game calls luaL_openlibs from 0x0165F180
        // This is likely in a game initialization function
        
        long callerOffset = 0x0165F180;
        Address callerAddr = toAddr(BASE + callerOffset);
        
        println("--- Analyzing call site at 0x0165F180 ---");
        
        // Find the function containing this call
        Function callerFunc = getFunctionContaining(callerAddr);
        if (callerFunc != null) {
            long funcOffset = callerFunc.getEntryPoint().getOffset() - BASE;
            long funcSize = callerFunc.getBody().getNumAddresses();
            println(String.format("  In function: 0x%08X (%s), %d bytes", 
                funcOffset, callerFunc.getName(), funcSize));
            
            // Show instructions around the call
            println("\n  Instructions around the luaL_openlibs call:");
            showInstructionsAround(callerAddr, 10, 10);
            
            // What calls this function?
            println("\n  What calls this function?");
            findCallers(funcOffset);
            
            // Check if this function stores lua_State to a global
            println("\n  Global variable references in this function:");
            findGlobalRefs(callerFunc);
            
        } else {
            println("  No function defined at this location!");
            println("  This might be in a .rdata thunk or virtual table");
            
            // Show raw instructions
            println("\n  Raw instructions at 0x0165F180:");
            showInstructionsAt(callerAddr, 20);
        }
        
        // Also analyze the two Lua init wrappers
        println("\n\n=== Analyzing FUN_140d85400 (calls luaL_openlibs) ===");
        analyzeFunction(0x00D85400);
        
        println("\n\n=== Analyzing FUN_140d854d0 (calls luaL_openlibs) ===");
        analyzeFunction(0x00D854D0);
        
        // Check the global variables found earlier
        println("\n\n=== Checking potential lua_State globals ===");
        checkGlobal(0x01139B48, "lua_State candidate 1");
        checkGlobal(0x01139B50, "lua_State candidate 2");
        checkGlobal(0x01137060, "lua_State candidate 3");
    }
    
    private void showInstructionsAround(Address center, int before, int after) {
        Listing listing = currentProgram.getListing();
        
        // Go back 'before' instructions
        Address addr = center;
        for (int i = 0; i < before; i++) {
            Instruction prev = listing.getInstructionBefore(addr);
            if (prev != null) {
                addr = prev.getAddress();
            }
        }
        
        // Now show instructions
        InstructionIterator iter = listing.getInstructions(addr, true);
        int count = 0;
        while (iter.hasNext() && count < (before + after + 1)) {
            Instruction inst = iter.next();
            String marker = inst.getAddress().equals(center) ? " <-- CALL" : "";
            long offset = inst.getAddress().getOffset() - BASE;
            println(String.format("    0x%08X: %s%s", offset, inst.toString(), marker));
            count++;
        }
    }
    
    private void showInstructionsAt(Address start, int count) {
        Listing listing = currentProgram.getListing();
        InstructionIterator iter = listing.getInstructions(start, true);
        int i = 0;
        while (iter.hasNext() && i < count) {
            Instruction inst = iter.next();
            long offset = inst.getAddress().getOffset() - BASE;
            println(String.format("    0x%08X: %s", offset, inst.toString()));
            i++;
        }
    }
    
    private void findCallers(long funcOffset) {
        Address funcAddr = toAddr(BASE + funcOffset);
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        ReferenceIterator refs = refMgr.getReferencesTo(funcAddr);
        
        int count = 0;
        while (refs.hasNext() && count < 10) {
            Reference ref = refs.next();
            Address fromAddr = ref.getFromAddress();
            long fromOffset = fromAddr.getOffset() - BASE;
            
            Function func = getFunctionContaining(fromAddr);
            String funcName = func != null ? func.getName() : "unknown";
            long funcStart = func != null ? func.getEntryPoint().getOffset() - BASE : 0;
            
            println(String.format("    Called from 0x%08X in %s (0x%08X)", 
                fromOffset, funcName, funcStart));
            count++;
        }
        
        if (count == 0) {
            println("    No callers found!");
        }
    }
    
    private void findGlobalRefs(Function func) {
        Listing listing = currentProgram.getListing();
        InstructionIterator iter = listing.getInstructions(func.getBody(), true);
        
        java.util.Set<String> seen = new java.util.HashSet<>();
        
        while (iter.hasNext()) {
            Instruction inst = iter.next();
            String repr = inst.toString();
            
            // Look for references to data segment (0x141xxxxxx)
            if (repr.contains("0x141") || repr.contains("0x142")) {
                // Extract the address
                java.util.regex.Pattern p = java.util.regex.Pattern.compile("0x14[12][0-9a-fA-F]{6}");
                java.util.regex.Matcher m = p.matcher(repr);
                while (m.find()) {
                    String addrStr = m.group();
                    if (!seen.contains(addrStr)) {
                        seen.add(addrStr);
                        long globalAddr = Long.parseLong(addrStr.substring(2), 16);
                        long globalOffset = globalAddr - BASE;
                        println(String.format("    0x%08X: %s", globalOffset, repr));
                    }
                }
            }
        }
    }
    
    private void analyzeFunction(long offset) {
        Address addr = toAddr(BASE + offset);
        Function func = getFunctionAt(addr);
        
        if (func == null) {
            println("  No function at this address");
            return;
        }
        
        long size = func.getBody().getNumAddresses();
        int paramCount = func.getParameterCount();
        
        println(String.format("  Size: %d bytes, Parameters: %d", size, paramCount));
        
        // Show first 15 instructions
        println("  First instructions:");
        Listing listing = currentProgram.getListing();
        InstructionIterator iter = listing.getInstructions(addr, true);
        int count = 0;
        while (iter.hasNext() && count < 15) {
            Instruction inst = iter.next();
            if (!func.getBody().contains(inst.getAddress())) break;
            long instOffset = inst.getAddress().getOffset() - BASE;
            println(String.format("    0x%08X: %s", instOffset, inst.toString()));
            count++;
        }
        
        // What does this function call?
        println("\n  Functions called:");
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        AddressIterator addrIter = func.getBody().getAddresses(true);
        java.util.Set<Long> calledFuncs = new java.util.HashSet<>();
        
        while (addrIter.hasNext()) {
            Address insnAddr = addrIter.next();
            Reference[] refs = refMgr.getReferencesFrom(insnAddr);
            for (Reference ref : refs) {
                if (ref.getReferenceType().isCall()) {
                    long targetOffset = ref.getToAddress().getOffset() - BASE;
                    if (!calledFuncs.contains(targetOffset)) {
                        calledFuncs.add(targetOffset);
                        Function target = getFunctionAt(ref.getToAddress());
                        String name = target != null ? target.getName() : "unknown";
                        println(String.format("    0x%08X - %s", targetOffset, name));
                    }
                }
            }
        }
    }
    
    private void checkGlobal(long offset, String description) {
        Address addr = toAddr(BASE + offset);
        println(String.format("\n  %s at 0x%08X:", description, offset));
        
        // Check what references this address
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        ReferenceIterator refs = refMgr.getReferencesTo(addr);
        
        int count = 0;
        while (refs.hasNext() && count < 10) {
            Reference ref = refs.next();
            Address fromAddr = ref.getFromAddress();
            long fromOffset = fromAddr.getOffset() - BASE;
            
            Function func = getFunctionContaining(fromAddr);
            String funcName = func != null ? func.getName() : "unknown";
            
            // Get the instruction
            Instruction inst = currentProgram.getListing().getInstructionAt(fromAddr);
            String instStr = inst != null ? inst.toString() : "?";
            
            println(String.format("    0x%08X in %s: %s", fromOffset, funcName, instStr));
            count++;
        }
        
        if (count == 0) {
            println("    No references found");
        }
    }
}
