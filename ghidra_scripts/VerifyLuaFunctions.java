//Verify candidate Lua functions by examining their code
//@category COA
//@author COA Script Extender

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;

public class VerifyLuaFunctions extends GhidraScript {
    
    private long BASE = 0x140000000L;
    
    @Override
    public void run() throws Exception {
        println("=== Verifying Lua Function Candidates ===\n");
        
        // lua_setglobal candidate
        println("--- Candidate: lua_setglobal at 0x00D773F0 ---");
        analyzeFunction(0x00D773F0);
        
        // Push function candidates
        println("\n--- Candidate push functions near lua_pushstring ---");
        analyzeFunction(0x00D7A440);
        analyzeFunction(0x00D7A470);
        analyzeFunction(0x00D7A900);
        
        // Accessor candidate
        println("\n--- Candidate accessor near lua_type ---");
        analyzeFunction(0x00D6F260);
        
        // Look for lua_gettop - should be very small, just return L->top - L->base
        println("\n--- Searching for lua_gettop (very small stack query) ---");
        findLuaGettop();
        
        // Look for lua_tonumber, lua_tostring, lua_toboolean
        println("\n--- Searching for lua_to* functions ---");
        findToFunctions();
        
        println("\n=== Summary of Likely Functions ===");
        println("lua_setglobal    = 0x00D773F0  (wrapper around lua_setfield)");
        println("lua_pushnumber   = 0x00D7A440  (48 bytes, near pushstring)");
        println("lua_pushboolean  = 0x00D7A470  (50 bytes)");
        println("lua_gettop       = (see above)");
    }
    
    private void analyzeFunction(long offset) {
        Address addr = toAddr(BASE + offset);
        Function func = getFunctionAt(addr);
        
        if (func == null) {
            println(String.format("  0x%08X - No function defined", offset));
            return;
        }
        
        int paramCount = func.getParameterCount();
        String retType = func.getReturnType().getName();
        long size = func.getBody().getNumAddresses();
        
        println(String.format("  0x%08X: %s %s(%d params), %d bytes",
            offset, retType, func.getName(), paramCount, size));
        
        // Show first few instructions
        Listing listing = currentProgram.getListing();
        InstructionIterator iter = listing.getInstructions(addr, true);
        int count = 0;
        while (iter.hasNext() && count < 8) {
            Instruction inst = iter.next();
            if (!func.getBody().contains(inst.getAddress())) break;
            println("    " + inst.toString());
            count++;
        }
    }
    
    private void findLuaGettop() {
        // lua_gettop is typically: return (int)(L->top - L->base) / sizeof(TValue)
        // Very small function, likely 10-20 bytes
        
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator iter = fm.getFunctions(true);
        
        while (iter.hasNext()) {
            Function func = iter.next();
            long size = func.getBody().getNumAddresses();
            
            // lua_gettop is tiny - typically under 20 bytes
            if (size >= 10 && size <= 30) {
                Address addr = func.getEntryPoint();
                long offset = addr.getOffset() - BASE;
                
                // Should be near other Lua stack functions (around 0x00D6F000 - 0x00D70000)
                if (offset >= 0x00D6F000 && offset <= 0x00D70000) {
                    // Check if it looks like lua_gettop (single parameter, returns int)
                    String name = func.getName();
                    if (name.contains("gettop") || 
                        (func.getParameterCount() <= 1 && 
                         func.getReturnType().getName().contains("int"))) {
                        println(String.format("  Candidate: 0x%08X (%d bytes) - %s", 
                            offset, size, name));
                    }
                }
            }
        }
        
        // Also check right before lua_settop (0x00D6F090)
        // lua_gettop is often right before or after lua_settop
        println("  Checking near lua_settop (0x00D6F090):");
        for (long off = 0x00D6F000; off < 0x00D6F090; off += 0x10) {
            Address addr = toAddr(BASE + off);
            Function func = getFunctionAt(addr);
            if (func != null) {
                long size = func.getBody().getNumAddresses();
                if (size <= 30) {
                    println(String.format("    0x%08X (%d bytes) - %s", 
                        off, size, func.getName()));
                }
            }
        }
    }
    
    private void findToFunctions() {
        // lua_tonumber, lua_tostring, lua_toboolean typically:
        // - Take lua_State* and index
        // - Return the converted value
        // - Are medium-sized functions (30-100 bytes)
        
        // They should be near lua_type (0x00D6F630)
        println("  Functions in range 0x00D6F200 - 0x00D6F800:");
        
        FunctionManager fm = currentProgram.getFunctionManager();
        Address start = toAddr(BASE + 0x00D6F200);
        Address end = toAddr(BASE + 0x00D6F800);
        
        FunctionIterator iter = fm.getFunctions(start, true);
        
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getEntryPoint().compareTo(end) > 0) break;
            
            long offset = func.getEntryPoint().getOffset() - BASE;
            long size = func.getBody().getNumAddresses();
            String name = func.getName();
            
            // Skip lua_type which we already know
            if (offset == 0x00D6F630) continue;
            
            println(String.format("    0x%08X (%3d bytes) - %s", offset, size, name));
        }
        
        // Also check near lua_pushstring for lua_tostring
        println("\n  Functions in range 0x00D7A000 - 0x00D7B000 (near pushstring):");
        start = toAddr(BASE + 0x00D7A000);
        end = toAddr(BASE + 0x00D7B000);
        
        iter = fm.getFunctions(start, true);
        
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getEntryPoint().compareTo(end) > 0) break;
            
            long offset = func.getEntryPoint().getOffset() - BASE;
            long size = func.getBody().getNumAddresses();
            String name = func.getName();
            
            // Skip lua_pushstring which we already know
            if (offset == 0x00D7AC60) continue;
            
            println(String.format("    0x%08X (%3d bytes) - %s", offset, size, name));
        }
    }
}
