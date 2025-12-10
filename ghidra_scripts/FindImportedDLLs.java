// FindImportedDLLs.java
// Lists all DLLs imported by the game executable
// These are candidates for proxy DLL injection
// @category COA

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import java.util.*;

public class FindImportedDLLs extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== Finding Imported DLLs ===");
        println("Looking for proxy DLL candidates...\n");
        
        ExternalManager extMgr = currentProgram.getExternalManager();
        String[] libraryNames = extMgr.getExternalLibraryNames();
        
        // Categorize DLLs
        List<String> systemDlls = new ArrayList<>();
        List<String> runtimeDlls = new ArrayList<>();
        List<String> gameDlls = new ArrayList<>();
        List<String> proxyTargets = new ArrayList<>();
        
        // Good proxy DLL candidates (commonly used, easy to proxy)
        Set<String> goodProxies = new HashSet<>(Arrays.asList(
            "version.dll", "winmm.dll", "dinput8.dll", "dinput.dll",
            "dsound.dll", "d3d9.dll", "d3d11.dll", "dxgi.dll",
            "xinput1_3.dll", "xinput1_4.dll", "xinput9_1_0.dll",
            "binkw32.dll", "binkw64.dll"
        ));
        
        println("Imported DLLs:");
        println("----------------------------------------");
        
        for (String libName : libraryNames) {
            if (libName.equals("<EXTERNAL>")) continue;
            
            String lowerName = libName.toLowerCase();
            int funcCount = 0;
            
            // Count imported functions
            ExternalLocationIterator extLocs = extMgr.getExternalLocations(libName);
            while (extLocs.hasNext()) {
                extLocs.next();
                funcCount++;
            }
            
            // Categorize
            if (goodProxies.contains(lowerName)) {
                proxyTargets.add(libName + " (" + funcCount + " imports)");
                println("[PROXY TARGET] " + libName + " - " + funcCount + " functions");
            } else if (lowerName.startsWith("api-ms-") || lowerName.startsWith("ext-ms-")) {
                systemDlls.add(libName);
            } else if (lowerName.contains("vcruntime") || lowerName.contains("msvc") || 
                       lowerName.contains("ucrtbase") || lowerName.equals("kernel32.dll") ||
                       lowerName.equals("user32.dll") || lowerName.equals("ntdll.dll") ||
                       lowerName.equals("advapi32.dll") || lowerName.equals("gdi32.dll")) {
                runtimeDlls.add(libName);
                println("[RUNTIME]      " + libName + " - " + funcCount + " functions");
            } else if (lowerName.endsWith(".dll")) {
                gameDlls.add(libName);
                println("[GAME/OTHER]   " + libName + " - " + funcCount + " functions");
            }
        }
        
        println("\n========================================");
        println("RECOMMENDED PROXY DLL TARGETS");
        println("========================================");
        
        if (proxyTargets.isEmpty()) {
            println("No common proxy targets found.");
            println("Consider these alternatives:");
            for (String dll : gameDlls) {
                println("  - " + dll);
            }
        } else {
            println("Best options (in order of preference):");
            // Prioritize
            String[] priority = {"version.dll", "winmm.dll", "dinput8.dll", "dsound.dll"};
            int rank = 1;
            for (String prio : priority) {
                for (String target : proxyTargets) {
                    if (target.toLowerCase().startsWith(prio)) {
                        println("  " + rank + ". " + target);
                        rank++;
                    }
                }
            }
            // Then the rest
            for (String target : proxyTargets) {
                boolean found = false;
                for (String prio : priority) {
                    if (target.toLowerCase().startsWith(prio)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    println("  " + rank + ". " + target);
                    rank++;
                }
            }
        }
        
        println("\n========================================");
        println("SUMMARY");
        println("========================================");
        println("Total DLLs imported: " + libraryNames.length);
        println("Proxy candidates: " + proxyTargets.size());
        println("Game DLLs: " + gameDlls.size());
        println("Runtime DLLs: " + runtimeDlls.size());
    }
}
