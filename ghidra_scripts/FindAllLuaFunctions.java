//Find all Lua API functions for COA Script Extender
//@author COA Script Extender Team
//@category Lua
//@keybinding
//@menupath Analysis.Find All Lua Functions
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import java.util.*;
import java.io.*;

public class FindAllLuaFunctions extends GhidraScript {

    // Known Lua error strings and their associated functions
    private static final String[][] STRING_SIGNATURES = {
        // String, Expected Function, Notes
        {"too many upvalues", "luaL_setfuncs", "Check caller for lua_pushcclosure"},
        {"stack overflow", "lua_checkstack or luaL_*", "Common in many functions"},
        {"C stack overflow", "lua_resume/luaD_call", "Stack depth check"},
        {"cannot resume non-suspended coroutine", "lua_resume", "Coroutine state check"},
        {"cannot resume dead coroutine", "lua_resume", "Coroutine state check"},
        {"table overflow", "luaH_resize", "NOT lua_createtable!"},
        {"attempt to yield across", "lua_yieldk", "Yield check"},
        {"invalid index", "stack functions", "lua_gettop/settop area"},
        {"nil or table expected", "lua_setmetatable", "Metatable functions"},
        {"'for' initial value must be a number", "luaV_execute", "VM opcode 0x21"},
        {"upvalue", "debug functions", "debug.getupvalue etc"},
        {"_G", "lua_pushglobaltable", "Global table access"},
        {"_ENV", "environment access", "Lua 5.2+ environment"},
    };

    // Known Lua type tags (Lua 5.2)
    private static final int LUA_TNIL = 0;
    private static final int LUA_TBOOLEAN = 1;
    private static final int LUA_TLIGHTUSERDATA = 2;
    private static final int LUA_TNUMBER = 3;
    private static final int LUA_TSTRING = 4;
    private static final int LUA_TTABLE = 5;
    private static final int LUA_TFUNCTION = 6;
    private static final int LUA_TUSERDATA = 7;
    private static final int LUA_TTHREAD = 8;
    
    // Type tags we see in decompiled code
    private static final int LUA_TLCF = 0x16;  // 22 - light C function
    private static final int LUA_TCCL = 0x66;  // 102 - C closure (with upvalues)
    private static final int LUA_TTBL = 0x45;  // 69 - table

    private Map<String, Address> foundStrings = new HashMap<>();
    private Map<String, FunctionInfo> foundFunctions = new HashMap<>();
    private PrintWriter output;

    class FunctionInfo {
        Address address;
        String name;
        String signature;
        String confidence;
        String notes;
        List<Address> callers = new ArrayList<>();
        List<Address> callees = new ArrayList<>();
        
        FunctionInfo(Address addr, String name, String sig, String conf, String notes) {
            this.address = addr;
            this.name = name;
            this.signature = sig;
            this.confidence = conf;
            this.notes = notes;
        }
    }

    @Override
    public void run() throws Exception {
        // Create output file
        File outFile = new File(getProgramFile().getParentFile(), "lua_functions_found.txt");
        output = new PrintWriter(new FileWriter(outFile));
        
        println("=== COA Script Extender - Lua Function Finder ===");
        println("Output file: " + outFile.getAbsolutePath());
        output.println("=== Lua Function Analysis for " + getProgramFile().getName() + " ===");
        output.println("Generated: " + new java.util.Date());
        output.println("Base Address: " + currentProgram.getImageBase());
        output.println();

        // Step 1: Find all relevant strings
        println("\n[Step 1] Searching for Lua-related strings...");
        findLuaStrings();

        // Step 2: Find functions by string references
        println("\n[Step 2] Finding functions by string references...");
        findFunctionsByStrings();

        // Step 3: Find lua_pushcclosure (critical for our hook)
        println("\n[Step 3] Finding lua_pushcclosure...");
        findLuaPushCClosure();

        // Step 4: Find lua_createtable (our current blocker)
        println("\n[Step 4] Finding lua_createtable...");
        findLuaCreateTable();

        // Step 5: Find lua_setfield and lua_setglobal
        println("\n[Step 5] Finding lua_setfield/lua_setglobal...");
        findLuaSetFunctions();

        // Step 6: Find basic stack functions
        println("\n[Step 6] Finding stack manipulation functions...");
        findStackFunctions();

        // Step 7: Analyze luaV_execute for more functions
        println("\n[Step 7] Analyzing luaV_execute for internal calls...");
        analyzeLuaVExecute();

        // Step 8: Generate summary
        println("\n[Step 8] Generating summary...");
        generateSummary();

        output.close();
        println("\n=== Analysis Complete ===");
        println("Results saved to: " + outFile.getAbsolutePath());
    }

    private void findLuaStrings() throws Exception {
        Memory memory = currentProgram.getMemory();
        AddressSet searchSet = new AddressSet(currentProgram.getMemory().getLoadedAndInitializedAddressSet());
        
        String[] searchStrings = {
            "too many upvalues",
            "stack overflow",
            "C stack overflow", 
            "cannot resume",
            "table overflow",
            "invalid index",
            "attempt to yield",
            "nil or table expected",
            "'for' initial value",
            "_G",
            "_ENV",
            "upvalue",
            "getupvalue",
            "setupvalue",
            "newtable",
            "createtable",
            "setfield",
            "setglobal",
            "getfield",
            "getglobal",
            "pushcclosure",
            "pushcfunction",
            "pcall",
            "xpcall",
            "coroutine",
            "resume",
            "yield",
            "rawset",
            "rawget",
            "error",
            "lua_",  // Any debug strings containing lua_
        };

        output.println("=== String Search Results ===");
        
        for (String searchStr : searchStrings) {
            Address addr = memory.findBytes(searchSet.getMinAddress(), 
                searchStr.getBytes(), null, true, monitor);
            
            while (addr != null && !monitor.isCancelled()) {
                foundStrings.put(searchStr + "@" + addr, addr);
                output.println(String.format("  0x%s: \"%s\"", addr.toString(), searchStr));
                
                // Find next occurrence
                try {
                    addr = memory.findBytes(addr.add(1), 
                        searchStr.getBytes(), null, true, monitor);
                } catch (Exception e) {
                    break;
                }
            }
        }
        
        println("  Found " + foundStrings.size() + " string matches");
        output.println("\nTotal strings found: " + foundStrings.size());
        output.println();
    }

    private void findFunctionsByStrings() throws Exception {
        output.println("=== Functions Found by String References ===");
        
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        for (Map.Entry<String, Address> entry : foundStrings.entrySet()) {
            String strKey = entry.getKey();
            Address strAddr = entry.getValue();
            
            // Find references to this string
            Reference[] refs = refMgr.getReferencesTo(strAddr);
            
            for (Reference ref : refs) {
                Address fromAddr = ref.getFromAddress();
                Function func = funcMgr.getFunctionContaining(fromAddr);
                
                if (func != null) {
                    String funcName = func.getName();
                    Address funcAddr = func.getEntryPoint();
                    
                    output.println(String.format("  String \"%s\" referenced by:", 
                        strKey.split("@")[0]));
                    output.println(String.format("    Function: %s at 0x%s", 
                        funcName, funcAddr.toString()));
                    output.println(String.format("    Reference from: 0x%s", 
                        fromAddr.toString()));
                    
                    // Try to identify the function
                    identifyFunction(func, strKey.split("@")[0]);
                }
            }
        }
        output.println();
    }

    private void identifyFunction(Function func, String triggerString) {
        Address addr = func.getEntryPoint();
        String name = func.getName();
        int paramCount = func.getParameterCount();
        long size = func.getBody().getNumAddresses();
        
        // Heuristics based on string and function characteristics
        String identified = "unknown";
        String confidence = "low";
        
        if (triggerString.contains("too many upvalues") && size < 500) {
            identified = "luaL_setfuncs";
            confidence = "high";
        } else if (triggerString.contains("cannot resume") && triggerString.contains("coroutine")) {
            identified = "lua_resume";
            confidence = "high";
        } else if (triggerString.contains("table overflow") && size < 300) {
            identified = "luaH_resize (NOT lua_createtable!)";
            confidence = "high";
        } else if (triggerString.contains("C stack overflow") && size > 200) {
            identified = "luaD_call or lua_resume";
            confidence = "medium";
        } else if (triggerString.contains("'for' initial value") && size > 3000) {
            identified = "luaV_execute";
            confidence = "high";
        }
        
        if (!identified.equals("unknown")) {
            FunctionInfo info = new FunctionInfo(addr, identified, 
                "params=" + paramCount + ", size=" + size, confidence, triggerString);
            foundFunctions.put(identified, info);
            
            output.println(String.format("    >>> IDENTIFIED: %s (confidence: %s)", 
                identified, confidence));
        }
    }

    private void findLuaPushCClosure() throws Exception {
        output.println("=== Finding lua_pushcclosure ===");
        
        // lua_pushcclosure signature characteristics:
        // - Takes 3 params: lua_State* L, lua_CFunction fn, int n
        // - If n==0: writes type 0x16 (LUA_TLCF) - light C function
        // - If n>0: allocates closure, writes type 0x66 (LUA_TCCL)
        // - Writes to L->top (offset +0x10)
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Memory mem = currentProgram.getMemory();
        
        // Search for functions that write 0x16 and 0x66 type tags
        println("  Searching for functions with light C function (0x16) and C closure (0x66) patterns...");
        
        // Look for the pattern: mov dword ptr [reg+8], 0x16
        // This is setting the type tag for a light C function
        byte[] pattern16 = new byte[] { (byte)0xC7, 0x40, 0x08, 0x16, 0x00, 0x00, 0x00 };
        byte[] pattern66 = new byte[] { (byte)0xC7, 0x40, 0x08, 0x66, 0x00, 0x00, 0x00 };
        
        AddressSet searchSet = new AddressSet(mem.getLoadedAndInitializedAddressSet());
        
        // Find 0x16 pattern
        Address addr16 = mem.findBytes(searchSet.getMinAddress(), pattern16, null, true, monitor);
        Set<Function> candidates = new HashSet<>();
        
        while (addr16 != null && !monitor.isCancelled()) {
            Function func = funcMgr.getFunctionContaining(addr16);
            if (func != null) {
                candidates.add(func);
            }
            try {
                addr16 = mem.findBytes(addr16.add(1), pattern16, null, true, monitor);
            } catch (Exception e) {
                break;
            }
        }
        
        // Find 0x66 pattern and intersect
        Address addr66 = mem.findBytes(searchSet.getMinAddress(), pattern66, null, true, monitor);
        Set<Function> candidates66 = new HashSet<>();
        
        while (addr66 != null && !monitor.isCancelled()) {
            Function func = funcMgr.getFunctionContaining(addr66);
            if (func != null) {
                candidates66.add(func);
            }
            try {
                addr66 = mem.findBytes(addr66.add(1), pattern66, null, true, monitor);
            } catch (Exception e) {
                break;
            }
        }
        
        // Functions that have BOTH patterns are strong candidates
        candidates.retainAll(candidates66);
        
        output.println("  Candidates with both 0x16 and 0x66 type tags:");
        for (Function func : candidates) {
            long size = func.getBody().getNumAddresses();
            int params = func.getParameterCount();
            output.println(String.format("    0x%s: %s (size=%d, params=%d)", 
                func.getEntryPoint(), func.getName(), size, params));
            
            // lua_pushcclosure should be ~100-300 bytes
            if (size > 80 && size < 400) {
                output.println("      >>> LIKELY lua_pushcclosure!");
                
                FunctionInfo info = new FunctionInfo(func.getEntryPoint(), 
                    "lua_pushcclosure", 
                    "void(L, fn, n)", 
                    "high",
                    "Has both 0x16 and 0x66 type patterns, size=" + size);
                foundFunctions.put("lua_pushcclosure", info);
            }
        }
        output.println();
    }

    private void findLuaCreateTable() throws Exception {
        output.println("=== Finding lua_createtable ===");
        
        // lua_createtable characteristics:
        // - Takes 3 params: lua_State* L, int narray, int nrec  
        // - Calls luaH_new internally
        // - Pushes table onto stack (writes to L->top, type 0x45 = table)
        // - Increments L->top by 0x10
        
        // First find luaH_new (we identified this earlier)
        FunctionInfo luaHNew = foundFunctions.get("luaH_new");
        if (luaHNew == null) {
            // Search for luaH_new by pattern - creates table structure
            println("  Searching for luaH_new first...");
            findLuaHNew();
            luaHNew = foundFunctions.get("luaH_new");
        }
        
        if (luaHNew != null) {
            println("  Found luaH_new at " + luaHNew.address);
            output.println("  luaH_new located at: 0x" + luaHNew.address);
            
            // Find all callers of luaH_new
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            FunctionManager funcMgr = currentProgram.getFunctionManager();
            
            Reference[] refs = refMgr.getReferencesTo(luaHNew.address);
            output.println("  Functions calling luaH_new:");
            
            for (Reference ref : refs) {
                if (ref.getReferenceType().isCall()) {
                    Function caller = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (caller != null) {
                        long size = caller.getBody().getNumAddresses();
                        int params = caller.getParameterCount();
                        
                        output.println(String.format("    0x%s: %s (size=%d, params=%d)",
                            caller.getEntryPoint(), caller.getName(), size, params));
                        
                        // lua_createtable should:
                        // - Be relatively small (50-150 bytes)
                        // - Have 3 parameters
                        // - Write type 0x45 (table) to stack
                        if (size > 40 && size < 200 && params >= 2) {
                            // Check if it writes to L->top (offset +0x10)
                            if (checkWritesToLuaTop(caller)) {
                                output.println("      >>> LIKELY lua_createtable!");
                                
                                FunctionInfo info = new FunctionInfo(caller.getEntryPoint(),
                                    "lua_createtable",
                                    "void(L, narray, nrec)",
                                    "high",
                                    "Calls luaH_new, writes to L->top, size=" + size);
                                foundFunctions.put("lua_createtable", info);
                            }
                        }
                    }
                }
            }
        } else {
            output.println("  ERROR: Could not find luaH_new");
        }
        output.println();
    }

    private void findLuaHNew() throws Exception {
        // luaH_new characteristics:
        // - Takes 1 param: lua_State* L
        // - Allocates table structure
        // - Returns Table*
        // - Size around 60-120 bytes
        // - Calls allocation function and initializes table fields
        
        // Look for pattern: initializing table with 0xff00 (LUA_TNIL << 8 | LUA_TNIL)
        // or writing &DAT_* (empty hash part) to table+0x20
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcs = funcMgr.getFunctions(true);
        
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            long size = func.getBody().getNumAddresses();
            
            // luaH_new should be 60-150 bytes with 1-2 parameters
            if (size >= 50 && size <= 180) {
                int params = func.getParameterCount();
                if (params >= 1 && params <= 3) {
                    // Check for characteristic pattern
                    // luaH_new typically has: 
                    //   mov word ptr [reg+0xa], 0xff
                    //   mov dword ptr [reg+0x38], 0 (array size = 0)
                    
                    String funcName = func.getName();
                    Address addr = func.getEntryPoint();
                    
                    // Heuristic: look for functions that set multiple table fields
                    // by checking instruction count
                    int instCount = 0;
                    InstructionIterator instrs = currentProgram.getListing()
                        .getInstructions(func.getBody(), true);
                    while (instrs.hasNext()) {
                        instrs.next();
                        instCount++;
                    }
                    
                    // luaH_new has about 15-40 instructions
                    if (instCount >= 12 && instCount <= 50) {
                        output.println(String.format("  luaH_new candidate: 0x%s %s (size=%d, insts=%d)",
                            addr, funcName, size, instCount));
                    }
                }
            }
        }
    }

    private boolean checkWritesToLuaTop(Function func) {
        // Check if function writes to offset +0x10 (L->top)
        // Pattern: mov [rcx+10h], ... or similar
        
        try {
            InstructionIterator instrs = currentProgram.getListing()
                .getInstructions(func.getBody(), true);
            
            while (instrs.hasNext()) {
                Instruction inst = instrs.next();
                String mnemonic = inst.getMnemonicString();
                
                if (mnemonic.equals("MOV") || mnemonic.equals("ADD")) {
                    String repr = inst.toString();
                    if (repr.contains("+0x10]") || repr.contains("+10h]") || 
                        repr.contains("+ 0x10]") || repr.contains(",0x10")) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return false;
    }

    private void findLuaSetFunctions() throws Exception {
        output.println("=== Finding lua_setfield / lua_setglobal ===");
        
        // lua_setfield: void lua_setfield(lua_State *L, int idx, const char *k)
        // lua_setglobal: void lua_setglobal(lua_State *L, const char *name) 
        //                (macro that calls lua_setfield with LUA_GLOBALSINDEX)
        
        // These functions:
        // - Pop a value from stack
        // - Set it as field in a table
        // - Decrement L->top
        
        // Look for functions that:
        // 1. Read from L->top
        // 2. Decrement L->top by 0x10
        // 3. Call a table lookup/set function
        
        Memory mem = currentProgram.getMemory();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Pattern for decrementing stack: sub qword ptr [rcx+10h], 10h
        // or: add qword ptr [rcx+10h], -10h
        // In bytes this varies, so search by function characteristics
        
        FunctionIterator funcs = funcMgr.getFunctions(true);
        int candidateCount = 0;
        
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            long size = func.getBody().getNumAddresses();
            int params = func.getParameterCount();
            
            // lua_setfield should be ~100-250 bytes, 3 params
            // lua_setglobal should be smaller, 2 params (or inlined to setfield)
            if (size >= 80 && size <= 300 && params >= 2 && params <= 4) {
                // Check for stack decrement pattern
                if (checkStackDecrement(func)) {
                    candidateCount++;
                    if (candidateCount <= 20) {
                        output.println(String.format("  Candidate: 0x%s %s (size=%d, params=%d)",
                            func.getEntryPoint(), func.getName(), size, params));
                    }
                }
            }
        }
        
        output.println("  Total candidates: " + candidateCount);
        output.println();
    }

    private boolean checkStackDecrement(Function func) {
        try {
            InstructionIterator instrs = currentProgram.getListing()
                .getInstructions(func.getBody(), true);
            
            while (instrs.hasNext()) {
                Instruction inst = instrs.next();
                String repr = inst.toString().toLowerCase();
                
                // Look for: sub [reg+0x10], 0x10 or add [reg+0x10], -0x10
                if ((repr.contains("sub") || repr.contains("add")) && 
                    repr.contains("0x10")) {
                    return true;
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return false;
    }

    private void findStackFunctions() throws Exception {
        output.println("=== Finding Stack Manipulation Functions ===");
        
        // lua_gettop: int lua_gettop(lua_State *L)
        //   Returns (L->top - L->base) / sizeof(TValue)
        //   Very small function, ~20-40 bytes
        
        // lua_settop: void lua_settop(lua_State *L, int idx)
        //   Sets L->top based on idx
        //   ~50-100 bytes
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcs = funcMgr.getFunctions(true);
        
        List<Function> gettopCandidates = new ArrayList<>();
        List<Function> settopCandidates = new ArrayList<>();
        
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            long size = func.getBody().getNumAddresses();
            int params = func.getParameterCount();
            
            // lua_gettop: very small, 1 param, returns int
            if (size >= 15 && size <= 50 && params <= 2) {
                // Check for subtraction pattern (top - base)
                if (checkSubtractionPattern(func)) {
                    gettopCandidates.add(func);
                }
            }
            
            // lua_settop: small-medium, 2 params
            if (size >= 40 && size <= 120 && params >= 1 && params <= 3) {
                // Check for conditional logic (handling negative indices)
                if (checkConditionalStackOp(func)) {
                    settopCandidates.add(func);
                }
            }
        }
        
        output.println("  lua_gettop candidates:");
        for (Function f : gettopCandidates) {
            output.println(String.format("    0x%s: %s (size=%d)", 
                f.getEntryPoint(), f.getName(), f.getBody().getNumAddresses()));
        }
        
        output.println("  lua_settop candidates:");
        for (Function f : settopCandidates) {
            if (settopCandidates.indexOf(f) < 10) {
                output.println(String.format("    0x%s: %s (size=%d)",
                    f.getEntryPoint(), f.getName(), f.getBody().getNumAddresses()));
            }
        }
        output.println("  (Total settop candidates: " + settopCandidates.size() + ")");
        output.println();
    }

    private boolean checkSubtractionPattern(Function func) {
        try {
            InstructionIterator instrs = currentProgram.getListing()
                .getInstructions(func.getBody(), true);
            
            boolean hasSub = false;
            boolean hasSar = false;  // Shift arithmetic right (divide by 16)
            
            while (instrs.hasNext()) {
                Instruction inst = instrs.next();
                String mnem = inst.getMnemonicString();
                
                if (mnem.equals("SUB")) hasSub = true;
                if (mnem.equals("SAR") || mnem.equals("SHR")) hasSar = true;
            }
            
            return hasSub && hasSar;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkConditionalStackOp(Function func) {
        try {
            InstructionIterator instrs = currentProgram.getListing()
                .getInstructions(func.getBody(), true);
            
            int jumpCount = 0;
            boolean hasStackWrite = false;
            
            while (instrs.hasNext()) {
                Instruction inst = instrs.next();
                String mnem = inst.getMnemonicString();
                
                if (mnem.startsWith("J") && !mnem.equals("JMP")) jumpCount++;
                if (mnem.equals("MOV")) {
                    String repr = inst.toString();
                    if (repr.contains("+0x10]")) hasStackWrite = true;
                }
            }
            
            return jumpCount >= 1 && hasStackWrite;
        } catch (Exception e) {
            return false;
        }
    }

    private void analyzeLuaVExecute() throws Exception {
        output.println("=== Analyzing luaV_execute for Internal Calls ===");
        
        // Find luaV_execute - it's the largest Lua function (4000+ bytes)
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcs = funcMgr.getFunctions(true);
        
        Function luaVExecute = null;
        long maxSize = 0;
        
        // Find largest function in the Lua code region
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            long size = func.getBody().getNumAddresses();
            Address addr = func.getEntryPoint();
            
            // Lua functions are typically in the 0x140D6xxxx - 0x140D8xxxx range
            long offset = addr.getOffset();
            if (offset > 0x140D60000L && offset < 0x140D90000L) {
                if (size > maxSize) {
                    maxSize = size;
                    luaVExecute = func;
                }
            }
        }
        
        if (luaVExecute != null) {
            output.println("  luaV_execute found at: 0x" + luaVExecute.getEntryPoint());
            output.println("  Size: " + maxSize + " bytes");
            
            FunctionInfo info = new FunctionInfo(luaVExecute.getEntryPoint(),
                "luaV_execute", 
                "void(L)", 
                "high",
                "Largest function in Lua region, size=" + maxSize);
            foundFunctions.put("luaV_execute", info);
            
            // Find all functions called by luaV_execute
            output.println("  Functions called by luaV_execute:");
            
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            AddressIterator addrIter = refMgr.getReferenceSourceIterator(
                luaVExecute.getBody(), true);
            
            Set<Function> calledFuncs = new HashSet<>();
            while (addrIter.hasNext()) {
                Address fromAddr = addrIter.next();
                Reference[] refs = refMgr.getReferencesFrom(fromAddr);
                
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isCall()) {
                        Function callee = funcMgr.getFunctionAt(ref.getToAddress());
                        if (callee != null) {
                            calledFuncs.add(callee);
                        }
                    }
                }
            }
            
            // Sort by address
            List<Function> sortedFuncs = new ArrayList<>(calledFuncs);
            sortedFuncs.sort((a, b) -> a.getEntryPoint().compareTo(b.getEntryPoint()));
            
            for (Function f : sortedFuncs) {
                long size = f.getBody().getNumAddresses();
                output.println(String.format("    0x%s: %s (size=%d)",
                    f.getEntryPoint(), f.getName(), size));
            }
        }
        output.println();
    }

    private void generateSummary() throws Exception {
        output.println("\n" + "=".repeat(60));
        output.println("SUMMARY - FOUND FUNCTIONS");
        output.println("=".repeat(60));
        
        output.println("\nVerified/High Confidence:");
        output.println("-".repeat(40));
        
        for (Map.Entry<String, FunctionInfo> entry : foundFunctions.entrySet()) {
            FunctionInfo info = entry.getValue();
            if (info.confidence.equals("high")) {
                long offset = info.address.getOffset() - 0x140000000L;
                output.println(String.format("  %-25s 0x%08X  (RVA: 0x%s)",
                    info.name, offset, info.address));
                output.println(String.format("    Signature: %s", info.signature));
                output.println(String.format("    Notes: %s", info.notes));
            }
        }
        
        output.println("\nMedium/Low Confidence:");
        output.println("-".repeat(40));
        
        for (Map.Entry<String, FunctionInfo> entry : foundFunctions.entrySet()) {
            FunctionInfo info = entry.getValue();
            if (!info.confidence.equals("high")) {
                long offset = info.address.getOffset() - 0x140000000L;
                output.println(String.format("  %-25s 0x%08X  (confidence: %s)",
                    info.name, offset, info.confidence));
            }
        }
        
        output.println("\n" + "=".repeat(60));
        output.println("C++ DEFINES FOR coa_lua_bridge.cpp:");
        output.println("=".repeat(60));
        output.println();
        
        for (Map.Entry<String, FunctionInfo> entry : foundFunctions.entrySet()) {
            FunctionInfo info = entry.getValue();
            if (info.confidence.equals("high")) {
                long offset = info.address.getOffset() - 0x140000000L;
                String defName = info.name.toUpperCase().replace("LUA", "LUA_") + "_OFFSET";
                defName = defName.replace("__", "_");
                output.println(String.format("#define %-30s 0x%08X  // %s",
                    defName, offset, info.notes));
            }
        }
        
        output.println("\n" + "=".repeat(60));
        output.println("STILL NEEDED:");
        output.println("=".repeat(60));
        
        String[] needed = {
            "lua_createtable - creates table and pushes to stack",
            "lua_setfield - sets field in table",
            "lua_setglobal - sets global variable",
            "lua_gettop - gets stack top index",
            "lua_settop - sets stack top",
            "lua_pushstring - pushes string to stack",
            "lua_pushnumber - pushes number to stack",
            "lua_pushboolean - pushes boolean to stack"
        };
        
        for (String n : needed) {
            String funcName = n.split(" - ")[0];
            if (!foundFunctions.containsKey(funcName)) {
                output.println("  [ ] " + n);
            } else {
                output.println("  [x] " + n + " (FOUND)");
            }
        }
        
        // Print to console too
        println("\n=== SUMMARY ===");
        println("Found " + foundFunctions.size() + " functions");
        for (Map.Entry<String, FunctionInfo> entry : foundFunctions.entrySet()) {
            FunctionInfo info = entry.getValue();
            long offset = info.address.getOffset() - 0x140000000L;
            println(String.format("  %s: 0x%08X (%s)", info.name, offset, info.confidence));
        }
    }
}
