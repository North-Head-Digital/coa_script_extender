//Generate byte signatures (AOB patterns) for Lua functions to use for runtime scanning
//@category COA
//@author COA Script Extender

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.io.*;

public class GenerateLuaSignatures extends GhidraScript {

    private PrintWriter out;

    @Override
    public void run() throws Exception {
        String userHome = System.getProperty("user.home");
        String outputPath = userHome + "/coa_script_extender/ghidra_output/lua_signatures.txt";
        new File(userHome + "/coa_script_extender/ghidra_output").mkdirs();
        out = new PrintWriter(new FileWriter(outputPath));
        
        println("=== Generating Lua Function Signatures ===");
        out.println("=== Lua Function Byte Signatures (AOB Patterns) ===");
        out.println("Use these for runtime signature scanning to survive game updates");
        out.println();
        out.println("Format: SIGNATURE_NAME = \"XX XX XX ?? XX\" // description");
        out.println("?? = wildcard byte (varies between builds)");
        out.println();
        
        Memory mem = currentProgram.getMemory();
        
        // Functions we need signatures for (verified offsets)
        long[][] functions = {
            {0x140d6ab20L, 16, 0}, // lua_pushcclosure
            {0x140d69d40L, 16, 0}, // lua_createtable
            {0x140d6b670L, 20, 0}, // lua_setfield
            {0x140d6b9b0L, 16, 0}, // lua_settop
            {0x140d6e580L, 20, 0}, // luaL_setfuncs
            {0x140d6b0b0L, 16, 0}, // lua_rawgeti
            {0x140d6fd10L, 16, 0}, // lua_gettop (small function)
            {0x140d7ac60L, 16, 0}, // lua_pushstring
            {0x140d6adf0L, 16, 0}, // lua_pushvalue
        };
        
        String[] names = {
            "lua_pushcclosure",
            "lua_createtable", 
            "lua_setfield",
            "lua_settop",
            "luaL_setfuncs",
            "lua_rawgeti",
            "lua_gettop",
            "lua_pushstring",
            "lua_pushvalue"
        };
        
        for (int i = 0; i < functions.length; i++) {
            long addr = functions[i][0];
            int len = (int)functions[i][1];
            generateSignature(mem, addr, len, names[i]);
        }
        
        // Also output C++ code for signature scanning
        out.println();
        out.println("=== C++ Signature Scanner Code ===");
        out.println();
        out.println("#include <Windows.h>");
        out.println("#include <Psapi.h>");
        out.println("");
        out.println("struct Signature {");
        out.println("    const char* name;");
        out.println("    const char* pattern;");
        out.println("    const char* mask;");
        out.println("};");
        out.println("");
        out.println("// Pattern scan function");
        out.println("uintptr_t FindPattern(uintptr_t start, size_t size, const char* pattern, const char* mask) {");
        out.println("    size_t patternLen = strlen(mask);");
        out.println("    for (size_t i = 0; i < size - patternLen; i++) {");
        out.println("        bool found = true;");
        out.println("        for (size_t j = 0; j < patternLen; j++) {");
        out.println("            if (mask[j] == 'x' && pattern[j] != *(char*)(start + i + j)) {");
        out.println("                found = false;");
        out.println("                break;");
        out.println("            }");
        out.println("        }");
        out.println("        if (found) return start + i;");
        out.println("    }");
        out.println("    return 0;");
        out.println("}");
        
        out.close();
        println("Signatures written to: " + outputPath);
    }
    
    private void generateSignature(Memory mem, long addr, int len, String name) {
        try {
            Address funcAddr = toAddr(addr);
            Function func = getFunctionAt(funcAddr);
            
            out.println("// " + name + " at 0x" + Long.toHexString(addr));
            
            if (func != null) {
                out.println("// Function: " + func.getName() + ", Size: " + func.getBody().getNumAddresses() + " bytes");
            }
            
            // Read bytes
            byte[] bytes = new byte[len];
            mem.getBytes(funcAddr, bytes);
            
            // Generate pattern string and mask
            StringBuilder pattern = new StringBuilder();
            StringBuilder mask = new StringBuilder();
            StringBuilder hexPattern = new StringBuilder();
            
            for (int i = 0; i < bytes.length; i++) {
                int b = bytes[i] & 0xFF;
                
                // Wildcard bytes that are likely to change:
                // - Immediate values in the middle of instructions
                // - Offsets that might change with builds
                // For now, keep first 4 and last 4 bytes exact, wildcard middle offsets
                
                boolean isWildcard = false;
                
                // Common patterns that should be wildcarded:
                // - 4-byte offsets after certain opcodes
                // - Relative call targets
                
                pattern.append((char)b);
                
                if (isWildcard) {
                    mask.append('?');
                    hexPattern.append("?? ");
                } else {
                    mask.append('x');
                    hexPattern.append(String.format("%02X ", b));
                }
            }
            
            out.println("// Pattern: " + hexPattern.toString().trim());
            out.println("// Mask:    " + mask.toString());
            out.println("#define SIG_" + name.toUpperCase() + " \"" + escapeBytes(bytes) + "\"");
            out.println("#define MASK_" + name.toUpperCase() + " \"" + mask.toString() + "\"");
            out.println();
            
        } catch (Exception e) {
            out.println("// ERROR reading " + name + ": " + e.getMessage());
            out.println();
        }
    }
    
    private String escapeBytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append("\\x").append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }
}
