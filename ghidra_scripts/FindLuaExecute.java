// FindLuaExecute.java - Find luaV_execute and luaD_call (the actual Lua execution functions)
// @category COA
// @author COA Script Extender

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.Memory;

public class FindLuaExecute extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        println("=== Finding Lua execution functions ===");
        println("");
        
        Address baseAddr = currentProgram.getImageBase();
        long base = baseAddr.getOffset();
        FunctionManager fm = currentProgram.getFunctionManager();
        Memory mem = currentProgram.getMemory();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        
        // Key strings used by different Lua functions:
        String[][] searchStrings = {
            // {string, likely function}
            {"C stack overflow", "luaD_call / luaD_precall"},
            {"attempt to call a %s value", "luaD_precall"},
            {"call", "luaD_call"},
            {"'for' limit must be a number", "luaV_execute"},
            {"'for' step must be a number", "luaV_execute"},
            {"'for' initial value must be a number", "luaV_execute"},
            {"attempt to perform arithmetic on", "luaV_execute / arith"},
            {"__index", "luaV_gettable"},
            {"__newindex", "luaV_settable"},
            {"loop in gettable", "luaV_gettable"},
            {"loop in settable", "luaV_settable"},
        };
        
        println("Searching for Lua VM execution strings...\n");
        
        for (String[] entry : searchStrings) {
            String searchStr = entry[0];
            String likelyFunc = entry[1];
            
            Address found = mem.findBytes(baseAddr, searchStr.getBytes(), null, true, monitor);
            
            if (found != null) {
                println(String.format("Found \"%s\" at 0x%X", searchStr, found.getOffset()));
                println(String.format("  -> Likely: %s", likelyFunc));
                
                ReferenceIterator refs = refMgr.getReferencesTo(found);
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Address fromAddr = ref.getFromAddress();
                    Function func = fm.getFunctionContaining(fromAddr);
                    if (func != null) {
                        long offset = func.getEntryPoint().getOffset() - base;
                        long size = func.getBody().getNumAddresses();
                        println(String.format("    Referenced by: 0x%08X (size: %d bytes)", offset, size));
                    }
                }
                println("");
            }
        }
        
        // Now let's look for large functions in the Lua area - luaV_execute is usually HUGE
        println("\n=== Largest functions in Lua area (0xD60000-0xD90000) ===");
        println("(luaV_execute is typically 5000+ bytes)\n");
        
        AddressSet range = new AddressSet(baseAddr.add(0x00D60000), baseAddr.add(0x00D90000));
        FunctionIterator funcs = fm.getFunctions(range, true);
        
        // Collect and sort by size
        java.util.List<Object[]> funcList = new java.util.ArrayList<>();
        while (funcs.hasNext()) {
            Function func = funcs.next();
            long size = func.getBody().getNumAddresses();
            long offset = func.getEntryPoint().getOffset() - base;
            funcList.add(new Object[]{size, offset, func.getName()});
        }
        
        // Sort by size descending
        funcList.sort((a, b) -> Long.compare((Long)b[0], (Long)a[0]));
        
        // Print top 20
        int count = 0;
        for (Object[] entry : funcList) {
            if (count >= 20) break;
            println(String.format("  0x%08X: %s (%d bytes)", entry[1], entry[2], entry[0]));
            count++;
        }
        
        // Look for specific patterns in function prologs that indicate lua_call
        println("\n=== Looking for lua_call signature pattern ===");
        println("lua_call in Lua 5.2: void lua_call(lua_State *L, int nargs, int nresults)");
        println("This is typically a small function that calls luaD_call\n");
        
        // Functions between 50-200 bytes that might be lua_call wrapper
        count = 0;
        for (Object[] entry : funcList) {
            long size = (Long)entry[0];
            if (size >= 30 && size <= 200) {
                long offset = (Long)entry[1];
                // These are candidates for lua_call, lua_callk, lua_pcall, lua_pcallk
                if (offset >= 0x00D70000 && offset <= 0x00D72000) {
                    println(String.format("  Candidate: 0x%08X (%d bytes)", offset, size));
                    count++;
                    if (count >= 15) break;
                }
            }
        }
        
        println("\n=== Done ===");
    }
}
