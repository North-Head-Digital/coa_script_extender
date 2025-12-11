# Call to Arms: Gates of Hell - Script Extender
# CMake Build Configuration
#
# =============================================================================
# BUILD OPTIONS:
# =============================================================================
#
# Option 1: Windows (Native)
#   Prerequisites:
#     - Visual Studio 2019 or 2022 with C++ workload
#     - CMake 3.20+
#   Build:
#     mkdir build && cd build
#     cmake .. -G "Visual Studio 17 2022" -A x64
#     cmake --build . --config Release
#
# Option 2: Ubuntu (Cross-compile)
#   Prerequisites:
#     sudo apt install mingw-w64 cmake
#   Build:
#     ./build.sh
#   Or manually:
#     mkdir build && cd build
#     cmake .. -DCMAKE_TOOLCHAIN_FILE=../toolchain-mingw64.cmake
#     make -j$(nproc)
#
# Output:
#   Windows: build/Release/coa_extender.dll, build/Release/example_mod.dll
#   Linux:   build/coa_extender.dll, build/example_mod.dll
# =============================================================================

cmake_minimum_required(VERSION 3.20)
project(COA_ScriptExtender VERSION 1.0.0 LANGUAGES C CXX)

# C++17 for std::filesystem
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Cross-compilation check
if(CMAKE_CROSSCOMPILING AND MINGW)
    message(STATUS "Cross-compiling for Windows with MinGW")
    set(IS_MINGW_CROSS TRUE)
else()
    set(IS_MINGW_CROSS FALSE)
endif()

# Windows only (or cross-compiling to Windows)
if(NOT WIN32 AND NOT IS_MINGW_CROSS)
    message(FATAL_ERROR "This project only builds for Windows (native or cross-compile)")
endif()

# x64 only check (skip for cross-compile, handled by toolchain)
if(NOT IS_MINGW_CROSS AND NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "This project requires 64-bit build")
endif()

# Fetch MinHook source
include(FetchContent)
FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG        v1.3.3
)
FetchContent_GetProperties(minhook)
if(NOT minhook_POPULATED)
    FetchContent_Populate(minhook)
endif()

# Build MinHook as a static library ourselves
add_library(minhook STATIC
    ${minhook_SOURCE_DIR}/src/buffer.c
    ${minhook_SOURCE_DIR}/src/hook.c
    ${minhook_SOURCE_DIR}/src/trampoline.c
    ${minhook_SOURCE_DIR}/src/hde/hde32.c
    ${minhook_SOURCE_DIR}/src/hde/hde64.c
)
target_include_directories(minhook PUBLIC ${minhook_SOURCE_DIR}/include)
set_target_properties(minhook PROPERTIES LINKER_LANGUAGE C)

# SDK include directory
set(SDK_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/sdk)

#=============================================================================
# Compiler-specific settings
#=============================================================================

if(MSVC)
    # MSVC settings
    set(COA_COMPILE_OPTIONS /W3 /wd4996)
    set(COA_LINK_OPTIONS "")
elseif(MINGW OR IS_MINGW_CROSS)
    # MinGW settings (native or cross-compile)
    set(COA_COMPILE_OPTIONS -Wall -Wno-unknown-pragmas)
    set(COA_LINK_OPTIONS -static-libgcc -static-libstdc++)
else()
    message(WARNING "Unknown compiler, using default settings")
    set(COA_COMPILE_OPTIONS "")
    set(COA_LINK_OPTIONS "")
endif()

#=============================================================================
# Proxy DLL (version.dll) - This is what users put in the game folder
#=============================================================================

add_library(version_proxy SHARED
    proxy/version_proxy.cpp
)

set_target_properties(version_proxy PROPERTIES
    PREFIX ""
    OUTPUT_NAME "version"
    SUFFIX ".dll"
)

if(CMAKE_CONFIGURATION_TYPES)
    set_target_properties(version_proxy PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>"
    )
else()
    set_target_properties(version_proxy PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
endif()

target_compile_options(version_proxy PRIVATE ${COA_COMPILE_OPTIONS})
target_link_options(version_proxy PRIVATE ${COA_LINK_OPTIONS})

#=============================================================================
# Main Loader DLL
#=============================================================================

add_library(coa_extender SHARED
    sdk/coa_loader.cpp
    sdk/coa_api.cpp
    sdk/coa_lua_bridge.cpp
    sdk/coa_plugin_api.cpp
    sdk/coa_overlay.cpp
    sdk/coa_sdk.h
    sdk/coa_hooks.h
    sdk/coa_api.h
    sdk/coa_lua_bridge.h
    sdk/coa_plugin_api.h
    sdk/coa_plugin_api_internal.h
    sdk/coa_overlay.h
)

target_include_directories(coa_extender PRIVATE
    ${SDK_INCLUDE_DIR}
    ${minhook_SOURCE_DIR}/include
)

target_link_libraries(coa_extender PRIVATE
    minhook
    psapi  # For GetModuleInformation
)

# DLL properties
set_target_properties(coa_extender PROPERTIES
    OUTPUT_NAME "coa_extender"
    SUFFIX ".dll"
)

# Set output directory (different format for MSVC vs single-config generators)
if(CMAKE_CONFIGURATION_TYPES)
    set_target_properties(coa_extender PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>"
    )
else()
    set_target_properties(coa_extender PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
endif()

# Compiler options
target_compile_options(coa_extender PRIVATE ${COA_COMPILE_OPTIONS})
target_link_options(coa_extender PRIVATE ${COA_LINK_OPTIONS})

#=============================================================================
# Example Mod DLL
#=============================================================================

add_library(example_mod SHARED
    mods/example_mod.cpp
)

target_include_directories(example_mod PRIVATE
    ${SDK_INCLUDE_DIR}
    ${minhook_SOURCE_DIR}/include
)

# Link against the extender's import lib (optional, for shared functions)
# For now, mods just need the headers
target_link_libraries(example_mod PRIVATE
    minhook
)

set_target_properties(example_mod PROPERTIES
    OUTPUT_NAME "example_mod"
    SUFFIX ".dll"
)

# Set output directory
if(CMAKE_CONFIGURATION_TYPES)
    set_target_properties(example_mod PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>/mods"
    )
else()
    set_target_properties(example_mod PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/mods"
    )
endif()

# Compiler options
target_compile_options(example_mod PRIVATE ${COA_COMPILE_OPTIONS})
target_link_options(example_mod PRIVATE ${COA_LINK_OPTIONS})

#=============================================================================
# Installation
#=============================================================================

install(TARGETS coa_extender
    RUNTIME DESTINATION .
)

install(DIRECTORY ${CMAKE_BINARY_DIR}/$<CONFIG>/mods
    DESTINATION .
)

install(FILES
    sdk/coa_sdk.h
    sdk/coa_hooks.h
    sdk/coa_plugin_api.h
    DESTINATION sdk
)

install(FILES
    README.md
    DESTINATION .
)

#=============================================================================
# Package
#=============================================================================

set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_NAME "COA_ScriptExtender")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
include(CPack)
