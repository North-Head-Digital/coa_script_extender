// FindLuaCall.java - Find lua_call/lua_callk functions
// @category COA
// @author COA Script Extender

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.Memory;

public class FindLuaCall extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        println("=== Finding lua_call/lua_callk functions ===");
        println("");
        
        // In Lua 5.2, lua_pcallk and lua_callk are the internal functions
        // lua_pcall and lua_call are usually macros/wrappers
        
        // Known offset for lua_pcall: 0x00D712A0
        // Let's examine that function and find lua_callk nearby
        
        Address baseAddr = currentProgram.getImageBase();
        long base = baseAddr.getOffset();
        
        // These are the offsets we need to verify
        long[] luaFuncOffsets = {
            0x00D712A0,  // lua_pcall (known)
            0x00D70F10,  // nearby - could be lua_call
            0x00D71080,  // nearby
            0x00D71200,  // nearby
            0x00D71300,  // nearby
            0x00D71400,  // nearby
            0x00D6E580,  // lua_pushcclosure (known)
        };
        
        println("Checking functions near lua_pcall (0x00D712A0):");
        println("");
        
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // List all functions in the D70000-D75000 range (Lua call area)
        AddressSet range = new AddressSet(
            baseAddr.add(0x00D70000),
            baseAddr.add(0x00D75000)
        );
        
        FunctionIterator funcs = fm.getFunctions(range, true);
        while (funcs.hasNext()) {
            Function func = funcs.next();
            long offset = func.getEntryPoint().getOffset() - base;
            String name = func.getName();
            
            // Look for call-related functions
            String lowerName = name.toLowerCase();
            if (lowerName.contains("call") || 
                lowerName.contains("pcall") || 
                lowerName.contains("resume") ||
                lowerName.contains("execute") ||
                lowerName.contains("run")) {
                println(String.format("  INTERESTING: %s @ 0x%08X (offset 0x%08X)", 
                    name, func.getEntryPoint().getOffset(), offset));
            }
        }
        
        println("");
        println("All functions in Lua call region (0xD70000-0xD75000):");
        
        funcs = fm.getFunctions(range, true);
        int count = 0;
        while (funcs.hasNext() && count < 50) {
            Function func = funcs.next();
            long offset = func.getEntryPoint().getOffset() - base;
            println(String.format("  0x%08X: %s", offset, func.getName()));
            count++;
        }
        
        // Now search for string references that might indicate lua_call
        println("");
        println("Searching for lua_call-related strings...");
        
        String[] callStrings = {
            "attempt to yield across metamethod/C-call boundary",  // lua_callk
            "attempt to yield",  // lua_resume/lua_call
            "cannot resume non-suspended coroutine",  // lua_resume
            "cannot resume dead coroutine",  // lua_resume
        };
        
        for (String searchStr : callStrings) {
            println("");
            println("Looking for: \"" + searchStr + "\"");
            
            // Search memory for this string
            Memory mem = currentProgram.getMemory();
            Address found = mem.findBytes(
                baseAddr,
                searchStr.getBytes(),
                null,
                true,
                monitor
            );
            
            if (found != null) {
                println("  Found string at: " + found);
                
                // Find references to this string
                ReferenceManager refMgr = currentProgram.getReferenceManager();
                ReferenceIterator refs = refMgr.getReferencesTo(found);
                
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Address fromAddr = ref.getFromAddress();
                    Function func = fm.getFunctionContaining(fromAddr);
                    if (func != null) {
                        long offset = func.getEntryPoint().getOffset() - base;
                        println(String.format("  Referenced from: %s @ offset 0x%08X", 
                            func.getName(), offset));
                    }
                }
            }
        }
        
        // Also find luaD_call which is the internal dispatcher
        println("");
        println("Looking for luaD_call (internal call dispatcher)...");
        
        // luaD_call uses "C stack overflow" string
        Memory mem = currentProgram.getMemory();
        Address found = mem.findBytes(
            baseAddr,
            "C stack overflow".getBytes(),
            null,
            true,
            monitor
        );
        
        if (found != null) {
            println("  Found 'C stack overflow' at: " + found);
            
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            ReferenceIterator refs = refMgr.getReferencesTo(found);
            
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Address fromAddr = ref.getFromAddress();
                Function func = fm.getFunctionContaining(fromAddr);
                if (func != null) {
                    long offset = func.getEntryPoint().getOffset() - base;
                    println(String.format("  luaD_call candidate: %s @ offset 0x%08X", 
                        func.getName(), offset));
                }
            }
        }
        
        println("");
        println("=== Done ===");
    }
}
