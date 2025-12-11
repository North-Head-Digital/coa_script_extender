//Find how the GEM engine registers its own Lua commands/functions
//This will tell us the correct pattern for our own registration
//@category COA
//@author COA Script Extender

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.util.*;

public class FindGEMCommandRegistry extends GhidraScript {

    private PrintWriter out;
    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        String userHome = System.getProperty("user.home");
        String outputPath = userHome + "/coa_script_extender/ghidra_output/gem_command_registry.txt";
        new File(userHome + "/coa_script_extender/ghidra_output").mkdirs();
        out = new PrintWriter(new FileWriter(outputPath));
        
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        println("=== Finding GEM Engine Command Registration ===");
        out.println("=== GEM Engine Command/Trigger Registration Analysis ===");
        out.println();
        out.println("Looking for how the game registers its own Lua commands...");
        out.println("This will show us the correct pattern for our registration.");
        out.println();
        
        // Search for known GEM trigger command strings
        String[] knownCommands = {
            "actor_state",
            "camera_shake",
            "waypoint",
            "reinforcement",
            "scene_fade",
            "call_function",
            "g_link",
            "_VERSION",
            "assert",
            "print",
            "require"
        };
        
        DataIterator strings = currentProgram.getListing().getDefinedData(true);
        Map<String, List<Address>> commandRefs = new HashMap<>();
        
        for (String cmd : knownCommands) {
            commandRefs.put(cmd, new ArrayList<>());
        }
        
        // Find string references
        out.println("=== Searching for Command Strings ===");
        
        while (strings.hasNext()) {
            Data data = strings.next();
            if (data.getDataType() instanceof StringDataType || 
                data.getDataType().getName().contains("string")) {
                try {
                    String value = (String)data.getValue();
                    if (value != null) {
                        for (String cmd : knownCommands) {
                            if (value.equals(cmd) || value.contains(cmd)) {
                                out.println("Found '" + cmd + "' at " + data.getAddress());
                                commandRefs.get(cmd).add(data.getAddress());
                            }
                        }
                    }
                } catch (Exception e) {
                    // Skip non-string data
                }
            }
        }
        
        // Analyze references to these strings
        out.println();
        out.println("=== Analyzing Command Registration Patterns ===");
        
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        
        for (String cmd : knownCommands) {
            List<Address> addrs = commandRefs.get(cmd);
            if (addrs.isEmpty()) continue;
            
            out.println();
            out.println("--- " + cmd + " ---");
            
            for (Address strAddr : addrs) {
                // Find who references this string
                ReferenceIterator refs = refMgr.getReferencesTo(strAddr);
                
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Address from = ref.getFromAddress();
                    Function func = getFunctionContaining(from);
                    
                    if (func != null) {
                        out.println();
                        out.println("Referenced by: " + func.getName() + " at " + func.getEntryPoint());
                        out.println("  Reference at: " + from);
                        
                        // Decompile to see how it's used
                        DecompileResults results = decomp.decompileFunction(func, 30, monitor);
                        if (results.decompileCompleted()) {
                            String code = results.getDecompiledFunction().getC();
                            
                            // Look for registration patterns
                            if (code.contains("lua_register") || code.contains("luaL_") ||
                                code.contains("setfield") || code.contains("setglobal") ||
                                code.contains("d6ab20") || code.contains("d6b670") ||
                                code.contains("d6e580")) {
                                out.println("  ** LIKELY REGISTRATION FUNCTION **");
                            }
                            
                            // Print relevant lines
                            String[] lines = code.split("\n");
                            for (int i = 0; i < Math.min(40, lines.length); i++) {
                                out.println("  " + lines[i]);
                            }
                        }
                    }
                }
            }
        }
        
        // Also find luaopen_* functions (standard library registration)
        out.println();
        out.println("=== Looking for luaopen_* Library Functions ===");
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcs = funcMgr.getFunctions(true);
        
        while (funcs.hasNext()) {
            Function func = funcs.next();
            String name = func.getName().toLowerCase();
            
            if (name.contains("luaopen") || name.contains("lua_open")) {
                out.println();
                out.println("Found: " + func.getName() + " at " + func.getEntryPoint());
                out.println("  Params: " + func.getParameterCount());
                
                DecompileResults results = decomp.decompileFunction(func, 30, monitor);
                if (results.decompileCompleted()) {
                    String[] lines = results.getDecompiledFunction().getC().split("\n");
                    for (int i = 0; i < Math.min(30, lines.length); i++) {
                        out.println("  " + lines[i]);
                    }
                }
            }
        }
        
        // Look for the function that calls luaL_setfuncs multiple times (library opener)
        out.println();
        out.println("=== Finding Library Registration Pattern ===");
        
        // luaL_setfuncs at 0x140d6e580
        Address setfuncsAddr = toAddr(0x140d6e580L);
        ReferenceIterator setfuncsRefs = refMgr.getReferencesTo(setfuncsAddr);
        
        int count = 0;
        while (setfuncsRefs.hasNext() && count < 10) {
            Reference ref = setfuncsRefs.next();
            if (!ref.getReferenceType().isCall()) continue;
            
            Function caller = getFunctionContaining(ref.getFromAddress());
            if (caller == null) continue;
            
            out.println();
            out.println("luaL_setfuncs called by: " + caller.getName() + " at " + caller.getEntryPoint());
            
            DecompileResults results = decomp.decompileFunction(caller, 60, monitor);
            if (results.decompileCompleted()) {
                String[] lines = results.getDecompiledFunction().getC().split("\n");
                for (int i = 0; i < Math.min(50, lines.length); i++) {
                    out.println("  " + lines[i]);
                }
            }
            count++;
        }
        
        decomp.dispose();
        out.close();
        println("Analysis written to: " + outputPath);
    }
}
