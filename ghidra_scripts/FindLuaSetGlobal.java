//Find lua_setglobal and remaining Lua push/to functions
//@author COA Script Extender  
//@category COA.Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.util.*;

public class FindLuaSetGlobal extends GhidraScript {

    private static final long BASE = 0x140000000L;
    
    // Already found
    private static final long LUA_SETFIELD = 0x00D76D50;
    private static final long LUA_PUSHSTRING = 0x00D7AC60;
    
    @Override
    protected void run() throws Exception {
        println("=== Finding lua_setglobal and remaining functions ===");
        println("");
        
        // lua_setglobal in Lua 5.2 is typically:
        //   #define lua_setglobal(L,s) lua_setfield(L, LUA_GLOBALSINDEX, (s))
        // Or it calls lua_setfield internally with a special index
        
        // In Lua 5.2+, LUA_GLOBALSINDEX was replaced with LUA_REGISTRYINDEX
        // lua_setglobal now does: lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS)
        //                         lua_pushvalue(L, -2)
        //                         lua_setfield(L, -2, name)
        //                         lua_pop(L, 1)
        
        // Search for functions that call lua_setfield (0x00D76D50)
        println("Looking for functions that call lua_setfield...");
        println("(One of these is likely lua_setglobal)");
        println("");
        
        Address setFieldAddr = toAddr(BASE + LUA_SETFIELD);
        Reference[] refs = getReferencesTo(setFieldAddr);
        
        Set<Long> callers = new LinkedHashSet<>();
        for (Reference ref : refs) {
            if (ref.getReferenceType().isCall()) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    long offset = caller.getEntryPoint().getOffset() - BASE;
                    if (offset >= 0x00D60000 && offset <= 0x00DA0000) {
                        if (!callers.contains(offset)) {
                            callers.add(offset);
                            long size = caller.getBody().getNumAddresses();
                            println(String.format("  0x%08X (%d bytes) - %s", 
                                offset, size, caller.getName()));
                        }
                    }
                }
            }
        }
        
        // lua_setglobal is typically small (< 100 bytes) and calls lua_setfield once
        println("");
        println("Small callers of lua_setfield (likely lua_setglobal/lua_getglobal):");
        for (Long offset : callers) {
            Address addr = toAddr(BASE + offset);
            Function func = getFunctionAt(addr);
            if (func != null) {
                long size = func.getBody().getNumAddresses();
                if (size < 100) {
                    // Count calls to lua_setfield
                    int setFieldCalls = countCalls(func, setFieldAddr);
                    if (setFieldCalls == 1) {
                        println(String.format("  LIKELY lua_setglobal: 0x%08X (%d bytes, 1 call to setfield)", 
                            offset, size));
                    }
                }
            }
        }
        
        // Now find lua_pushnumber, lua_pushinteger, lua_pushboolean, lua_pushnil
        // These are typically very small functions (< 50 bytes) in the push region
        
        println("");
        println("========================================");
        println("Looking for push functions near lua_pushstring (0x00D7AC60)");
        println("========================================");
        println("");
        
        // lua_pushstring is at 0x00D7AC60
        // Other push functions are likely nearby
        Address pushStart = toAddr(BASE + 0x00D7A000);
        Address pushEnd = toAddr(BASE + 0x00D7B500);
        
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(pushStart, true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getEntryPoint().compareTo(pushEnd) > 0) break;
            
            long offset = func.getEntryPoint().getOffset() - BASE;
            long size = func.getBody().getNumAddresses();
            
            // Push functions are typically small
            if (size < 80) {
                println(String.format("  0x%08X (%d bytes) - %s", offset, size, func.getName()));
            }
        }
        
        // Look for lua_tostring (tolstring), lua_tonumber, lua_toboolean
        println("");
        println("========================================");
        println("Searching for lua_to* functions");
        println("========================================");
        println("");
        
        // These often reference type check error messages
        findByString("lua_tolstring", "'__tostring' must return a string", BASE);
        findByString("lua_tonumberx", "number has no integer representation", BASE);
        
        // Look near lua_type (0x00D6F630) for simple accessor functions
        println("");
        println("Small functions near lua_type (0x00D6F630):");
        Address typeStart = toAddr(BASE + 0x00D6EE00);
        Address typeEnd = toAddr(BASE + 0x00D6F800);
        
        iter = currentProgram.getFunctionManager().getFunctions(typeStart, true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getEntryPoint().compareTo(typeEnd) > 0) break;
            
            long offset = func.getEntryPoint().getOffset() - BASE;
            long size = func.getBody().getNumAddresses();
            
            if (size < 50) {
                println(String.format("  0x%08X (%d bytes) - %s", offset, size, func.getName()));
            }
        }
        
        println("");
        println("=== Analysis Complete ===");
        println("");
        println("RECOMMENDATION:");
        println("1. Examine small functions that call lua_setfield once -> lua_setglobal");
        println("2. Functions near 0x00D7AC60 are likely other push functions");
        println("3. Functions near 0x00D6F630 are likely type/stack accessors");
    }
    
    private int countCalls(Function func, Address target) {
        int count = 0;
        try {
            InstructionIterator iter = currentProgram.getListing().getInstructions(func.getBody(), true);
            while (iter.hasNext()) {
                Instruction inst = iter.next();
                if (inst.getMnemonicString().equals("CALL")) {
                    Reference[] refs = inst.getReferencesFrom();
                    for (Reference ref : refs) {
                        if (ref.getToAddress().equals(target)) {
                            count++;
                        }
                    }
                }
            }
        } catch (Exception e) {}
        return count;
    }
    
    private void findByString(String funcName, String searchStr, long base) {
        try {
            byte[] bytes = searchStr.getBytes();
            Address strAddr = currentProgram.getMemory().findBytes(
                currentProgram.getMinAddress(), bytes, null, true, monitor);
            
            if (strAddr != null) {
                Reference[] refs = getReferencesTo(strAddr);
                for (Reference ref : refs) {
                    Function func = getFunctionContaining(ref.getFromAddress());
                    if (func != null) {
                        long offset = func.getEntryPoint().getOffset() - base;
                        println(String.format("  %s = 0x%08X (via '%s')", 
                            funcName, offset, searchStr));
                        break;
                    }
                }
            }
        } catch (Exception e) {}
    }
}
