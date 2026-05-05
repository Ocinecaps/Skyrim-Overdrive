#pragma once

#include <atomic>
#include <cstdint>

namespace overdrive::d3dx {

// Phase 4: replace selected D3DX9 math functions with hand-rolled SSE
// implementations. Each replacement is hot-patched into d3dx9_42.dll via
// MinHook, so all in-process callers (Skyrim, ENB, ...) see our version.
//
// Returns true if at least one replacement was installed.
bool Install();

// Periodic stats logger (throttled internally to once per 5s) — writes the
// per-function call counts and per-second rates for every replacement.
void MaybeLogStats();

// Phase 3 target discovery — periodic dump (throttled to once per 10s) of
// the top return addresses per replaced D3DX function. The dominant retaddr
// is the Skyrim function looping over D3DX calls. Patch THAT function with
// ParallelFor to get multi-core CPU drawcall prep.
void MaybeLogCallerHistograms();

// Render thread TID, latched on first replacement call (since D3DX is hit
// almost exclusively from the render thread). Other modules can read this
// to decide which thread to profile / batch on. 0 until first call.
extern std::atomic<uint32_t> gRenderThreadId;

// Cumulative call counters per replaced function. Useful for verifying which
// functions actually get hit, and for HUD/external display.
extern std::atomic<uint32_t> gCount_MatrixMultiplyTranspose;
extern std::atomic<uint32_t> gCount_MatrixMultiply;
extern std::atomic<uint32_t> gCount_MatrixTranspose;
extern std::atomic<uint32_t> gCount_Vec3TransformCoord;
extern std::atomic<uint32_t> gCount_Vec3TransformNormal;
extern std::atomic<uint32_t> gCount_Vec3Normalize;
extern std::atomic<uint32_t> gCount_PlaneNormalize;

}
