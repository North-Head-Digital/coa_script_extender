-- COA Script Extender Test
-- This script tests if COA_Extender is properly registered

-- Test on script load
local function testExtender()
    if COA_Extender then
        print("=== COA SCRIPT EXTENDER TEST ===")
        print("COA_Extender table found!")
        
        -- Test GetVersion
        if COA_Extender.GetVersion then
            local version = COA_Extender.GetVersion()
            print("COA_Extender.GetVersion() = " .. tostring(version))
        else
            print("ERROR: GetVersion not found!")
        end
        
        -- Test Log
        if COA_Extender.Log then
            COA_Extender.Log("Hello from Lua! The Script Extender is working!")
            print("COA_Extender.Log() called successfully")
        else
            print("ERROR: Log not found!")
        end
        
        -- List all functions
        print("Available COA_Extender functions:")
        for k, v in pairs(COA_Extender) do
            print("  " .. k .. " = " .. type(v))
        end
        
        print("=== END TEST ===")
    else
        print("WARNING: COA_Extender not found! Script extender may not be loaded.")
    end
end

-- Run test immediately when script loads
testExtender()
