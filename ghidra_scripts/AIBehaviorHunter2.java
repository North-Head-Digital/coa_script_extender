// AIBehaviorHunter2.java - Extended AI, Animation, and Behavior Systems Hunter
// Run in Ghidra's Script Manager
// Searches for additional AI-related strings missed by the first pass
//
// @category Analysis
// @author COA Script Extender Project

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import java.util.*;
import java.io.*;

public class AIBehaviorHunter2 extends GhidraScript {

    // Output file for results
    private PrintWriter output;
    
    // Track all found functions to avoid duplicates
    private Set<String> allFoundFunctions = new HashSet<>();
    
    // Categories and their search strings
    private static final Map<String, String[]> SEARCH_CATEGORIES = new LinkedHashMap<>();
    
    static {
        // STANCE/POSTURE SYSTEM
        SEARCH_CATEGORIES.put("STANCE & POSTURE", new String[] {
            "stance", "prone", "crouch", "stand", "kneel", "posture",
            "lie", "crawl", "duck", "cover_position"
        });
        
        // PRIORITY/SCHEDULING
        SEARCH_CATEGORIES.put("TASK PRIORITY & SCHEDULING", new String[] {
            "priority", "queue", "schedule", "pending", "urgent",
            "immediate", "delay", "wait", "timeout", "cooldown"
        });
        
        // MORALE/PSYCHOLOGY
        SEARCH_CATEGORIES.put("MORALE & PSYCHOLOGY", new String[] {
            "flee", "rout", "retreat", "surrender", "panic",
            "morale", "fear", "courage", "bravery", "coward",
            "break", "rally", "suppress", "shock", "pin"
        });
        
        // ANIMATION SYSTEM
        SEARCH_CATEGORIES.put("ANIMATION SYSTEM", new String[] {
            "animation", "anim", "blend", "transition", "pose",
            "skeleton", "bone", "rig", "motion", "keyframe",
            "idle", "locomotion", "gesture", "action"
        });
        
        // TIMING/COOLDOWNS
        SEARCH_CATEGORIES.put("TIMING & COOLDOWNS", new String[] {
            "timer", "cooldown", "interval", "duration", "elapsed",
            "tick", "frame", "delta", "rate", "frequency"
        });
        
        // AI PERSONALITY
        SEARCH_CATEGORIES.put("AI PERSONALITY & AGGRESSION", new String[] {
            "aggression", "aggressive", "passive", "defensive",
            "cautious", "reckless", "bold", "coward", "brave",
            "personality", "behavior_type", "ai_type"
        });
        
        // COMBAT STATES
        SEARCH_CATEGORIES.put("COMBAT STATES", new String[] {
            "engage", "disengage", "reload", "aim", "fire",
            "burst", "suppress", "overwatch", "ambush", "assault",
            "hold_fire", "cease_fire", "weapons_free"
        });
        
        // AWARENESS/DETECTION
        SEARCH_CATEGORIES.put("AWARENESS & DETECTION", new String[] {
            "awareness", "alert", "alarm", "spotted", "visible",
            "hidden", "stealth", "noise", "sound", "hearing",
            "vision", "sight", "los", "line_of_sight", "fov"
        });
        
        // ORDERS/COMMANDS
        SEARCH_CATEGORIES.put("ORDERS & COMMANDS", new String[] {
            "order", "command", "directive", "instruction", "mission",
            "assign", "dispatch", "deploy", "reinforce", "support"
        });
        
        // NAVIGATION
        SEARCH_CATEGORIES.put("NAVIGATION & TERRAIN", new String[] {
            "navigate", "navigation", "terrain", "ground", "surface",
            "slope", "height", "elevation", "cliff", "water",
            "bridge", "road", "obstacle", "blocked", "impassable"
        });
        
        // VEHICLE-SPECIFIC
        SEARCH_CATEGORIES.put("VEHICLE AI", new String[] {
            "hull", "turret", "track", "wheel", "gear",
            "reverse", "pivot", "rotate", "traverse", "elevation",
            "gunner", "driver", "commander", "loader", "crew"
        });
        
        // INFANTRY-SPECIFIC
        SEARCH_CATEGORIES.put("INFANTRY AI", new String[] {
            "soldier", "infantry", "trooper", "rifleman", "gunner",
            "grenade", "melee", "bayonet", "close_combat", "hand_to_hand"
        });
        
        // SQUAD TACTICS
        SEARCH_CATEGORIES.put("SQUAD TACTICS", new String[] {
            "flank", "envelop", "pincer", "advance", "withdraw",
            "bound", "leapfrog", "cover_move", "smoke", "concealment"
        });
        
        // AI MANAGER/DIRECTOR
        SEARCH_CATEGORIES.put("AI MANAGEMENT", new String[] {
            "manager", "director", "controller", "handler", "dispatcher",
            "scheduler", "coordinator", "supervisor", "master", "brain"
        });
        
        // MEMORY/KNOWLEDGE
        SEARCH_CATEGORIES.put("AI MEMORY & KNOWLEDGE", new String[] {
            "memory", "remember", "forget", "know", "knowledge",
            "last_seen", "last_known", "position_history", "track"
        });
        
        // SCRIPTING/EVENTS
        SEARCH_CATEGORIES.put("SCRIPTING & EVENTS", new String[] {
            "script", "event", "trigger", "callback", "notify",
            "signal", "message", "broadcast", "listen", "handler"
        });
        
        // DIFFICULTY/SETTINGS
        SEARCH_CATEGORIES.put("DIFFICULTY & SETTINGS", new String[] {
            "difficulty", "easy", "normal", "hard", "veteran",
            "cheat", "bonus", "modifier", "multiplier", "scale"
        });
        
        // PHYSICS INTERACTION
        SEARCH_CATEGORIES.put("PHYSICS & COLLISION", new String[] {
            "physics", "collision", "raycast", "trace", "hit",
            "impact", "force", "momentum", "velocity", "acceleration"
        });
        
        // RESOURCE MANAGEMENT
        SEARCH_CATEGORIES.put("RESOURCE MANAGEMENT", new String[] {
            "resource", "supply", "ammo_count", "fuel_level", "repair",
            "reinforce", "resupply", "depot", "cache", "stockpile"
        });
    }

    @Override
    public void run() throws Exception {
        // Create output file
        File outputFile = new File(getProgramFile().getParentFile(), "coa_ai_extended.txt");
        output = new PrintWriter(new FileWriter(outputFile));
        
        println("===========================================");
        println("AIBehaviorHunter2 - Extended AI String Hunt");
        println("===========================================");
        println("Output: " + outputFile.getAbsolutePath());
        
        output.println("# Call to Arms: Extended AI & Behavior Functions");
        output.println("# Generated by AIBehaviorHunter2.java");
        output.println("# These expand on the initial AI function discovery");
        output.println();
        
        int totalFound = 0;
        
        // Process each category
        for (Map.Entry<String, String[]> category : SEARCH_CATEGORIES.entrySet()) {
            String categoryName = category.getKey();
            String[] searchStrings = category.getValue();
            
            output.println("========================================");
            output.println(categoryName);
            output.println("========================================");
            output.println();
            
            int categoryCount = 0;
            
            for (String searchStr : searchStrings) {
                if (monitor.isCancelled()) {
                    break;
                }
                
                int count = searchForString(searchStr, categoryName);
                categoryCount += count;
            }
            
            output.println("# " + categoryName + " total: " + categoryCount + " functions");
            output.println();
            
            totalFound += categoryCount;
            println(categoryName + ": " + categoryCount + " functions found");
        }
        
        // Summary
        output.println();
        output.println("========================================");
        output.println("SUMMARY");
        output.println("========================================");
        output.println("Total unique functions found: " + allFoundFunctions.size());
        output.println("Total search hits: " + totalFound);
        output.println();
        
        // Print all unique functions sorted by address
        output.println("========================================");
        output.println("ALL UNIQUE FUNCTIONS (SORTED BY ADDRESS)");
        output.println("========================================");
        
        List<String> sortedFuncs = new ArrayList<>(allFoundFunctions);
        Collections.sort(sortedFuncs);
        for (String func : sortedFuncs) {
            output.println(func);
        }
        
        // Generate hook points file
        generateHookPointsFile();
        
        output.close();
        
        println();
        println("===========================================");
        println("COMPLETE!");
        println("Total unique functions: " + allFoundFunctions.size());
        println("Results saved to: " + outputFile.getAbsolutePath());
        println("===========================================");
    }
    
    private int searchForString(String searchStr, String category) throws Exception {
        int foundCount = 0;
        Memory memory = currentProgram.getMemory();
        
        // Search for the string in memory
        byte[] searchBytes = searchStr.toLowerCase().getBytes();
        Address startAddr = currentProgram.getMinAddress();
        
        Set<Address> stringAddresses = new HashSet<>();
        
        // Find all occurrences of this string
        while (startAddr != null && !monitor.isCancelled()) {
            Address found = memory.findBytes(startAddr, searchBytes, null, true, monitor);
            if (found == null) {
                break;
            }
            stringAddresses.add(found);
            startAddr = found.add(1);
        }
        
        if (stringAddresses.isEmpty()) {
            output.println("String: '" + searchStr + "'");
            output.println("  -> NOT FOUND");
            output.println();
            return 0;
        }
        
        // Find functions that reference these strings
        Set<Function> referencingFunctions = new HashSet<>();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        for (Address strAddr : stringAddresses) {
            // Get references TO this string address
            ReferenceIterator refs = refMgr.getReferencesTo(strAddr);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Address fromAddr = ref.getFromAddress();
                Function func = funcMgr.getFunctionContaining(fromAddr);
                if (func != null) {
                    referencingFunctions.add(func);
                }
            }
            
            // Also check nearby addresses (strings might be referenced by nearby bytes)
            for (int offset = -4; offset <= 4; offset++) {
                try {
                    Address nearby = strAddr.add(offset);
                    ReferenceIterator nearbyRefs = refMgr.getReferencesTo(nearby);
                    while (nearbyRefs.hasNext()) {
                        Reference ref = nearbyRefs.next();
                        Address fromAddr = ref.getFromAddress();
                        Function func = funcMgr.getFunctionContaining(fromAddr);
                        if (func != null) {
                            referencingFunctions.add(func);
                        }
                    }
                } catch (Exception e) {
                    // Ignore address errors
                }
            }
        }
        
        if (referencingFunctions.isEmpty()) {
            output.println("String: '" + searchStr + "' (found " + stringAddresses.size() + " occurrences)");
            output.println("  -> No function references found");
            output.println();
            return 0;
        }
        
        output.println("String: '" + searchStr + "'");
        output.println("  Functions found: " + referencingFunctions.size());
        
        // Sort functions by address
        List<Function> sortedFuncs = new ArrayList<>(referencingFunctions);
        sortedFuncs.sort((a, b) -> a.getEntryPoint().compareTo(b.getEntryPoint()));
        
        for (Function func : sortedFuncs) {
            String funcName = func.getName();
            Address funcAddr = func.getEntryPoint();
            String addrStr = funcAddr.toString();
            
            // Generate a meaningful name if it's a default name
            String displayName = funcName;
            if (funcName.startsWith("FUN_") || funcName.startsWith("LAB_")) {
                displayName = generateFunctionName(searchStr, category, funcAddr);
            }
            
            output.println("  -> " + displayName + " @ " + addrStr);
            
            // Track unique functions
            allFoundFunctions.add(addrStr + " = " + displayName);
            foundCount++;
        }
        
        output.println();
        return foundCount;
    }
    
    private String generateFunctionName(String searchStr, String category, Address addr) {
        // Create a descriptive name based on category
        String prefix = "AI_";
        
        if (category.contains("STANCE")) {
            prefix = "AI_Stance_";
        } else if (category.contains("ANIMATION")) {
            prefix = "Anim_";
        } else if (category.contains("MORALE")) {
            prefix = "AI_Morale_";
        } else if (category.contains("PRIORITY")) {
            prefix = "AI_Task_";
        } else if (category.contains("TIMING")) {
            prefix = "AI_Timer_";
        } else if (category.contains("PERSONALITY")) {
            prefix = "AI_Personality_";
        } else if (category.contains("COMBAT")) {
            prefix = "AI_Combat_";
        } else if (category.contains("AWARENESS")) {
            prefix = "AI_Awareness_";
        } else if (category.contains("ORDERS")) {
            prefix = "AI_Order_";
        } else if (category.contains("NAVIGATION")) {
            prefix = "AI_Nav_";
        } else if (category.contains("VEHICLE")) {
            prefix = "AI_Vehicle_";
        } else if (category.contains("INFANTRY")) {
            prefix = "AI_Infantry_";
        } else if (category.contains("SQUAD")) {
            prefix = "AI_Squad_";
        } else if (category.contains("MANAGEMENT")) {
            prefix = "AI_Manager_";
        } else if (category.contains("MEMORY")) {
            prefix = "AI_Memory_";
        } else if (category.contains("SCRIPTING")) {
            prefix = "Script_";
        } else if (category.contains("DIFFICULTY")) {
            prefix = "Game_Difficulty_";
        } else if (category.contains("PHYSICS")) {
            prefix = "Physics_";
        } else if (category.contains("RESOURCE")) {
            prefix = "Resource_";
        }
        
        // Capitalize first letter of search string
        String suffix = searchStr.substring(0, 1).toUpperCase() + searchStr.substring(1);
        suffix = suffix.replace("_", "");
        
        return prefix + suffix + "_" + addr.toString();
    }
    
    private void generateHookPointsFile() throws Exception {
        File hookFile = new File(getProgramFile().getParentFile(), "coa_ai_extended_hooks.txt");
        PrintWriter hookOutput = new PrintWriter(new FileWriter(hookFile));
        
        hookOutput.println("# Extended AI Hook Points");
        hookOutput.println("# Ready for use with detours/hooking libraries");
        hookOutput.println("# Format: FunctionName = 0xOFFSET");
        hookOutput.println();
        
        // Parse and output hook points
        List<String> sortedFuncs = new ArrayList<>(allFoundFunctions);
        Collections.sort(sortedFuncs);
        
        for (String entry : sortedFuncs) {
            String[] parts = entry.split(" = ");
            if (parts.length == 2) {
                String addr = parts[0];
                String name = parts[1];
                
                // Convert full address to offset (remove base)
                String offset = addr;
                if (addr.startsWith("140")) {
                    offset = "0x0" + addr.substring(3);
                } else if (addr.startsWith("14")) {
                    offset = "0x" + addr.substring(2);
                }
                
                hookOutput.println(name + " = " + offset);
            }
        }
        
        hookOutput.close();
        println("Hook points saved to: " + hookFile.getAbsolutePath());
    }
}
