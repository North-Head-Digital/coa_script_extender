//Find how Lua is initialized in the game
//@category COA
//@author COA Script Extender

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;

public class FindLuaInitialization extends GhidraScript {
    
    private long BASE = 0x140000000L;
    
    // Known offsets
    private long LUAL_OPENLIBS = 0x00D85F90;
    private long LUA_NEWSTATE = 0x00000000; // Need to find
    private long LUAL_NEWSTATE = 0x00000000; // Need to find
    
    @Override
    public void run() throws Exception {
        println("=== Finding Lua Initialization ===\n");
        
        // Find what calls luaL_openlibs
        println("--- What calls luaL_openlibs (0x00D85F90)? ---");
        findCallers(LUAL_OPENLIBS);
        
        // Look for lua_newstate or luaL_newstate
        println("\n--- Searching for lua_newstate / luaL_newstate ---");
        findLuaNewstate();
        
        // Look for string references that indicate Lua initialization
        println("\n--- Searching for Lua initialization strings ---");
        findLuaInitStrings();
        
        // Check if game might use lua_State from a global variable
        println("\n--- Looking for global lua_State storage ---");
        findGlobalLuaState();
    }
    
    private void findCallers(long offset) {
        Address addr = toAddr(BASE + offset);
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        
        ReferenceIterator refs = refMgr.getReferencesTo(addr);
        int count = 0;
        
        while (refs.hasNext() && count < 20) {
            Reference ref = refs.next();
            Address fromAddr = ref.getFromAddress();
            long fromOffset = fromAddr.getOffset() - BASE;
            
            Function func = getFunctionContaining(fromAddr);
            String funcName = func != null ? func.getName() : "unknown";
            
            println(String.format("  Called from 0x%08X in %s", fromOffset, funcName));
            
            // If we found a function, show its size
            if (func != null) {
                long size = func.getBody().getNumAddresses();
                println(String.format("    Function at 0x%08X, size %d bytes", 
                    func.getEntryPoint().getOffset() - BASE, size));
            }
            count++;
        }
        
        if (count == 0) {
            println("  No callers found!");
        }
    }
    
    private void findLuaNewstate() {
        // lua_newstate and luaL_newstate are typically medium-sized functions
        // that return a lua_State* pointer
        
        // Search for functions that:
        // 1. Are in the Lua code region (0x00D6C000 - 0x00D90000)
        // 2. Allocate memory (call to malloc or similar)
        // 3. Return a pointer
        
        // Look for "luaL_newstate" or similar string patterns
        // Or search near luaL_openlibs since they're often called together
        
        Address openlibsAddr = toAddr(BASE + LUAL_OPENLIBS);
        
        // Search backwards for potential lua_newstate
        println("  Checking functions before luaL_openlibs:");
        
        FunctionManager fm = currentProgram.getFunctionManager();
        Address start = toAddr(BASE + 0x00D85000);
        Address end = toAddr(BASE + LUAL_OPENLIBS);
        
        FunctionIterator iter = fm.getFunctions(start, true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getEntryPoint().compareTo(end) >= 0) break;
            
            long offset = func.getEntryPoint().getOffset() - BASE;
            long size = func.getBody().getNumAddresses();
            
            // luaL_newstate is typically 50-150 bytes
            if (size >= 40 && size <= 200) {
                println(String.format("    0x%08X (%d bytes) - %s", offset, size, func.getName()));
            }
        }
        
        // Also check what luaL_openlibs calls internally
        println("\n  Functions called by luaL_openlibs:");
        Function openlibs = getFunctionAt(openlibsAddr);
        if (openlibs != null) {
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            AddressIterator addrIter = openlibs.getBody().getAddresses(true);
            
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
                            println(String.format("    Calls 0x%08X - %s", targetOffset, name));
                        }
                    }
                }
            }
        }
    }
    
    private void findLuaInitStrings() {
        // Search for strings that indicate Lua initialization
        String[] patterns = {
            "_G",           // Global table
            "_VERSION",     // Lua version string
            "Lua 5",        // Version identifier
            "package",      // Package library
            "require",      // Require function
            "lua.start",    // Game's Lua start
            "script",       // Script-related
            "LuaState",     // State reference
        };
        
        for (String pattern : patterns) {
            println("  Looking for '" + pattern + "':");
            
            // Use memory search for the string
            Address start = currentProgram.getMinAddress();
            Address end = currentProgram.getMaxAddress();
            
            byte[] bytes = pattern.getBytes();
            Address found = currentProgram.getMemory().findBytes(start, end, bytes, null, true, monitor);
            
            if (found != null) {
                println(String.format("    Found at 0x%08X", found.getOffset() - BASE));
                
                // Find references to this string
                ReferenceManager refMgr = currentProgram.getReferenceManager();
                ReferenceIterator refs = refMgr.getReferencesTo(found);
                int count = 0;
                while (refs.hasNext() && count < 5) {
                    Reference ref = refs.next();
                    long fromOffset = ref.getFromAddress().getOffset() - BASE;
                    Function func = getFunctionContaining(ref.getFromAddress());
                    String funcName = func != null ? func.getName() : "unknown";
                    println(String.format("      Referenced from 0x%08X in %s", fromOffset, funcName));
                    count++;
                }
            }
        }
    }
    
    private void findGlobalLuaState() {
        // The game might store lua_State* in a global variable
        // Look for .data/.bss references near Lua functions
        
        println("  Checking if luaL_openlibs stores to globals:");
        
        Address openlibsAddr = toAddr(BASE + LUAL_OPENLIBS);
        Function openlibs = getFunctionAt(openlibsAddr);
        
        if (openlibs != null) {
            // Check the caller functions for global storage patterns
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            ReferenceIterator refs = refMgr.getReferencesTo(openlibsAddr);
            
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    long callerOffset = caller.getEntryPoint().getOffset() - BASE;
                    println(String.format("\n  Analyzing caller: 0x%08X (%s)", callerOffset, caller.getName()));
                    
                    // Look for MOV instructions to data segment in the caller
                    Listing listing = currentProgram.getListing();
                    InstructionIterator instIter = listing.getInstructions(caller.getBody(), true);
                    
                    int storeCount = 0;
                    while (instIter.hasNext() && storeCount < 10) {
                        Instruction inst = instIter.next();
                        String mnemonic = inst.getMnemonicString();
                        
                        // Look for stores to absolute addresses (globals)
                        if (mnemonic.equals("MOV") || mnemonic.equals("LEA")) {
                            String repr = inst.toString();
                            // Check if it references an address in data segment
                            if (repr.contains("[0x14") && repr.contains("]")) {
                                println("    " + inst.getAddress() + ": " + repr);
                                storeCount++;
                            }
                        }
                    }
                }
            }
        }
    }
}
