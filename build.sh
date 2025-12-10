#!/bin/bash
# Build script for Call to Arms Script Extender
# Cross-compiles from Ubuntu to Windows x64

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Call to Arms Script Extender - Build${NC}"
echo -e "${GREEN}========================================${NC}"
echo

# Check for mingw
if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo -e "${RED}ERROR: mingw-w64 not found!${NC}"
    echo
    echo "Install with:"
    echo "  sudo apt update"
    echo "  sudo apt install mingw-w64 cmake build-essential git"
    echo
    exit 1
fi

echo -e "${GREEN}✓${NC} MinGW-w64 found: $(x86_64-w64-mingw32-g++ --version | head -n1)"

# Check for cmake
if ! command -v cmake &> /dev/null; then
    echo -e "${RED}ERROR: cmake not found!${NC}"
    echo "Install with: sudo apt install cmake"
    exit 1
fi

echo -e "${GREEN}✓${NC} CMake found: $(cmake --version | head -n1)"

# Parse arguments
CLEAN=false
VERBOSE=false
BUILD_TYPE="Release"

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean|-c)
            CLEAN=true
            shift
            ;;
        --debug|-d)
            BUILD_TYPE="Debug"
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            echo "Usage: ./build.sh [options]"
            echo
            echo "Options:"
            echo "  --clean, -c    Clean build directory before building"
            echo "  --debug, -d    Build in Debug mode (default: Release)"
            echo "  --verbose, -v  Verbose output"
            echo "  --help, -h     Show this help"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Clean if requested
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    rm -rf "$BUILD_DIR"
fi

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure
echo
echo -e "${GREEN}Configuring (${BUILD_TYPE})...${NC}"
echo

CMAKE_ARGS="-DCMAKE_TOOLCHAIN_FILE=$SCRIPT_DIR/toolchain-mingw64.cmake"
CMAKE_ARGS="$CMAKE_ARGS -DCMAKE_BUILD_TYPE=$BUILD_TYPE"

if [ "$VERBOSE" = true ]; then
    cmake $CMAKE_ARGS "$SCRIPT_DIR"
else
    cmake $CMAKE_ARGS "$SCRIPT_DIR" > /dev/null
fi

# Build
echo
echo -e "${GREEN}Building...${NC}"
echo

if [ "$VERBOSE" = true ]; then
    make -j$(nproc) VERBOSE=1
else
    make -j$(nproc)
fi

# Rename DLLs to remove lib prefix (Windows convention)
[ -f "$BUILD_DIR/libcoa_extender.dll" ] && mv "$BUILD_DIR/libcoa_extender.dll" "$BUILD_DIR/coa_extender.dll"
[ -f "$BUILD_DIR/mods/libexample_mod.dll" ] && mv "$BUILD_DIR/mods/libexample_mod.dll" "$BUILD_DIR/mods/example_mod.dll"

# Success!
echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}BUILD SUCCESSFUL!${NC}"
echo -e "${GREEN}========================================${NC}"
echo
echo "Output files:"
echo -e "  ${GREEN}$BUILD_DIR/coa_extender.dll${NC}"
echo -e "  ${GREEN}$BUILD_DIR/example_mod.dll${NC}"
echo
echo "To use:"
echo "  1. Copy coa_extender.dll to your game directory"
echo "  2. Create 'mods' folder in game directory"
echo "  3. Copy example_mod.dll to the mods folder"
echo "  4. Use a DLL injector or rename to a game-loaded DLL"
echo
