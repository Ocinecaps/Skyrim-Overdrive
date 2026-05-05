#pragma once

#include <atomic>
#include <vector>

struct IDirect3DDevice9;

namespace overdrive::d3d9hook {

// Phase 2.0: install IAT hook on Direct3DCreate9 in TESV.exe's import table.
// When Skyrim calls Direct3DCreate9, our wrapper runs, captures the returned
// IDirect3D9*, vtable-hooks IDirect3D9::CreateDevice. When CreateDevice fires,
// we capture the IDirect3DDevice9*, vtable-hook Present.
//
// Phase 2.5: also captures the back-buffer pixel data on every Present into
// a triple-buffered ring. Use TryGetLatestFrame() from any thread.
//
// Returns true if the IAT hook was installed (does NOT mean the chain has
// fired yet — that happens later when Skyrim's render setup runs).
bool Install();

// Counters readable from any thread (e.g., HUD overlay, log dumps).
extern std::atomic<unsigned long long> gPresentCount;
extern std::atomic<unsigned long long> gCreateDeviceCount;
extern std::atomic<unsigned long long> gDirect3DCreate9Count;

// Captured at the first Present call. The thread that calls Present IS the
// render thread that runs the entire D3D9 / NiDX9 pipeline. The sampling
// profiler reads this to know which thread to suspend+sample.
// Handle is opened with THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT.
extern std::atomic<unsigned long> gRenderThreadId;
extern std::atomic<void*>         gRenderThreadHandle;

// Most recently captured device. nullptr until CreateDevice has fired.
extern std::atomic<IDirect3DDevice9*> gDevice;

// Most recently captured back buffer dimensions/format from CreateDevice's
// presentation parameters. 0 until CreateDevice has fired.
extern std::atomic<unsigned int> gBackBufferWidth;
extern std::atomic<unsigned int> gBackBufferHeight;

// Phase 2.5 — captured back-buffer pixel data, ring-buffered for safe
// cross-thread reads from the worker thread.
struct CapturedFrame {
    std::vector<unsigned char> pixels;     // tightly packed BGRA (no row padding)
    unsigned int       width       = 0;
    unsigned int       height      = 0;
    unsigned int       format      = 0;    // D3DFORMAT enum value
    unsigned long long frameIndex  = 0;    // monotonic — matches gPresentCount
};

// Copy out the most recently captured frame. Returns false if nothing has been
// captured yet, or if the staged frame is the same one the caller already saw
// (caller passes its last-seen frameIndex via inOutLastSeen). Thread-safe;
// holds an internal slot lock for the duration of the copy.
bool TryGetLatestFrame(CapturedFrame& out, unsigned long long& inOutLastSeen);

// Re-scan loaded modules and hook any d3d9.dll instances that weren't present
// at Install() time. ENB lazily LoadLibrary's the real system32 d3d9.dll
// AFTER our DllMain ran, so the install-time scan only sees ENB's proxy.
// Call this periodically from the worker thread (e.g., every 5s for the first
// 30s of the game) — it's idempotent (already-hooked modules are skipped).
// Returns the number of NEW modules hooked on this call.
int RescanAndHookNewD3d9Modules();

// Walk every loaded d3d9 module's writable PE sections looking for static
// pointers to real-IDirect3DDevice9 instances (ENB's real-device global).
// Hooks any found via the same vtable bulk-hook + Mirror::Install path
// applied to wrappers. Idempotent — safe to call repeatedly. Call once
// after the rescan window completes (~30s post-Install). Returns the
// number of real-device candidates hooked on this call.
int ScanD3d9DataSectionsForRealDevice();

}
