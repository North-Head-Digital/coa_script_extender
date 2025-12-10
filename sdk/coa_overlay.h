/**
 * COA Script Extender - In-Game Overlay
 * 
 * Shows visual indication that the script extender is active.
 * Uses Windows GDI to draw text on the game window.
 * 
 * Methods:
 * 1. Hook Present/EndScene (D3D11) - Most reliable
 * 2. Create overlay window - Simpler but less integrated
 * 3. Hook game's text rendering - Best integration
 */

#pragma once

#include <cstdint>

namespace COA {
namespace Overlay {

// Initialize the overlay system
bool Initialize();

// Shutdown and cleanup
void Shutdown();

// Enable/disable overlay
void SetEnabled(bool enabled);
bool IsEnabled();

// Set overlay text
void SetText(const char* text);

// Set position (0.0-1.0 normalized screen coordinates)
void SetPosition(float x, float y);

// Set color (RGB 0-255)
void SetColor(int r, int g, int b);

} // namespace Overlay
} // namespace COA
