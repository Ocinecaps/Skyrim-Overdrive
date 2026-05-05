#include "BootstrapThread.h"
#include "DebugLogger.h"
#include "VulkanWindow.h"
#include "Globals.h"
#include "NiDX9Hooks.h"
#include "D3DXReplace.h"
#include "D3D9DeviceVtable.h"
#include "D3D9Mirror.h"
#include "ScenegraphProfiler.h"
#include "SleepProfiler.h"
#include "WaitProfiler.h"
#include "CrashDebugger.h"
#include "VulkanCommandQueue.h"
#include "ResourceMirror.h"
#include "DxbcAnalyzer.h"
#include "D3D9PipelineDispatcher.h"
#include "D3D9ReadProfiler.h"
#include "RenderPoolPatch.h"
#include "D3D9Hook.h"

#include <windows.h>
#include <dbghelp.h>
#include <chrono>

namespace overdrive {

// User directive: drop the SDL3+Vulkan visible window apparatus entirely.
// We're not displaying captured frames anywhere, so SDL/Vulkan init is dead
// weight. The worker thread is now a pure instrumentation loop — it sleeps
// and periodically logs the dedup / NiDX9 / D3DX / D3D9VT counters.
//
// Flip this to false to bring back the SDL3+Vulkan window for HUD work.
constexpr bool kInstrumentationOnlyMode = true;

// =============================================================================
// Pipeline kill switch — set to false to revert to pre-pipeline behavior
// =============================================================================
// When false, pipeline::Install() is never called; pipeline::IsActive() stays
// false; every Mirror_* wrapper falls through to its synchronous orig<>()
// path exactly as it did before Stage 2. Hot-sub recording still operates
// (Week-2 path). Use this to bisect whether a behavior change came from the
// pipeline architecture vs. the surrounding instrumentation.
//
// 2026-05-05: Re-disabled. Tested with ENB in chain (the user's required
// configuration); pipeline causes visual glitches on textures (and likely
// shadows / specific render-target consumers). Magic effects and most
// geometry render correctly, but textures don't show or flicker.
//
// Root cause: ENB's d3d9.dll proxy reads device state when running its
// post-pass effects. Our pipeline defers SetTexture/SetRenderTarget until
// the dispatcher drains. Between Skyrim's Set on our hook and the
// dispatcher's actual orig<>() call, ENB sees the OLD device state and
// makes wrong decisions (binds wrong texture, samples wrong RT). Our RT/DS
// shadows in Mirror_GetRenderTarget cover Skyrim's own reads but ENB
// bypasses those — it goes straight to the real device.
//
// Fix would require either dropping ENB compatibility (path the user
// rejected) or building cross-thread state visibility for ENB to read from
// (architecturally large; equivalent to building our own d3d9 wrapper).
// Neither fits the 1-month scope. Pipeline approach is shelved.
//
// Multi-core path forward: identify SAFE TESV render-prep loops (matrix
// transforms per object, visibility cull per cell, etc.) and patch them
// onto Skyrim's existing 6-worker pool via RunParallel. That avoids the
// D3D9 chain entirely — the multi-core work happens BEFORE the drawcalls,
// not on them.
constexpr bool kEnablePipeline = false;

namespace {

LONG WINAPI WorkerCrashFilter(EXCEPTION_POINTERS* info) {
    OD_LOG("[CRASH] code=0x%08X address=%p",
        info->ExceptionRecord->ExceptionCode,
        info->ExceptionRecord->ExceptionAddress);
    // Hand control back to the next handler (likely ENB's, then OS default).
    return EXCEPTION_CONTINUE_SEARCH;
}

// Pure instrumentation loop — no window, no Vulkan, no SDL. All performance
// optimization actually happens inline in the D3D9 vtable / mirror wrappers
// on Skyrim's render thread; this worker just exists to surface the metrics.
void RunInstrumentationLoop() {
    OD_LOG("[BOOT] worker entered instrumentation-only mode (no SDL/Vulkan window). "
           "All optimization runs inline in D3D9Mirror wrappers on the game's render thread.");

    // RenderPool's hook on sub_A5B050 was installed earlier from DllMain,
    // alongside d3d9hook/nidx9/d3dx — that's the only window early enough
    // to catch the pool ctor. MaybeLogStats below pumps the observer +
    // memory-scan fallback if the hook somehow missed.

    // CrashDebugger installs second so it catches crashes during the rest
    // of init. On any unhandled fatal exception, walks the stack and logs
    // each frame symbolically (Windows DLLs via dbghelp PDBs, TESV.exe via
    // our IDA-extraction symbol table) to skyrim_overdrive_crash.log. This
    // is the safety net for invasive engine patching.
    crashdbg::Install();

    // EIP-sampling profiler. Tells us what % of CPU is in each module / page,
    // and (after recent changes) which functions are calling waits.
    if (!profiler::Install()) {
        OD_LOG("[BOOT] profiler install failed (continuing without it)");
    }
    // Sleep-call profiler. Hooks kernel32!Sleep, captures the TESV.exe
    // caller VA on every call, and dumps top-N hot Sleep callers. This
    // identifies which of the 503 Sleep call sites in TESV.exe are actually
    // hit during gameplay — the candidates for our first EXE patches.
    if (!sleepprof::Install()) {
        OD_LOG("[BOOT] sleep profiler install failed (continuing without it)");
    }
    // Wait profiler — hooks WaitForSingleObject, WaitForSingleObjectEx,
    // WaitForMultipleObjects. The 58% of CPU in ZwWaitForSingleObject we
    // observed all flows through these APIs. There are 45 distinct call
    // sites in TESV.exe (extracted by user, see WaitForSingleObject Full
    // Views\). This identifies which 45 are actually hot during gameplay.
    if (!waitprof::Install()) {
        OD_LOG("[BOOT] wait profiler install failed (continuing without it)");
    }
    // Vulkan command queue scaffolding. v1: stub queue + drain thread that
    // counts pops without translating. Validates the SPSC ring throughput
    // under Skyrim's actual peak D3D9 call rate. If the queue can sustain
    // the rate without backpressure (depth stays low, dropped == 0), the
    // architecture is viable for the eventual real Vulkan submission path.
    if (!vkq::Install()) {
        OD_LOG("[BOOT] VulkanCommandQueue install failed (continuing without it)");
    }
    // Resource mirror — captures shader bytecode + buffer metadata at every
    // D3D9 CreateXxx so the eventual Vulkan-side allocator + DXBC->SPIR-V
    // translator have complete data to work from.
    resmirror::Install();

    // Pipeline dispatcher — multi-core threading scaffolding for the rendering
    // system. When kEnablePipeline is true, spawns a dedicated dispatcher
    // thread that owns calling orig<>() against the real D3D9 device. When
    // false (default during the visual-glitch bisect), the dispatcher is NOT
    // installed; every Mirror_* falls through to its synchronous orig<>()
    // path. This isolates whether the pipeline is the source of glitches.
    if (kEnablePipeline) {
        if (!pipeline::Install()) {
            OD_LOG("[BOOT] pipeline dispatcher install failed (continuing without it)");
        }
    } else {
        OD_LOG("[BOOT] pipeline dispatcher DISABLED (kEnablePipeline=false). "
               "All Mirror_* take the synchronous orig<>() path. "
               "Hot-sub recording (Week-2 path) remains active.");
    }

    // d3d9hook re-scan cadence: ENB lazily LoadLibrary's the real system32
    // d3d9.dll AFTER our DllMain enumeration. Re-scan every 1s for the
    // first 30s. After that, all relevant modules should be loaded.
    using clock = std::chrono::steady_clock;
    using namespace std::chrono;
    auto workerStart = clock::now();
    auto lastRescan  = clock::now() - seconds(2);
    bool rescanDone  = false;

    while (!gShouldExit.load(std::memory_order_relaxed)) {
        if (!rescanDone) {
            auto now = clock::now();
            auto sinceStart = duration_cast<seconds>(now - workerStart).count();
            auto sinceLast  = duration_cast<seconds>(now - lastRescan).count();
            if (sinceLast >= 1) {
                lastRescan = now;
                int n = overdrive::d3d9hook::RescanAndHookNewD3d9Modules();
                if (n > 0) {
                    OD_LOG("[D3D9] periodic rescan picked up %d new d3d9 module(s)", n);
                }
            }
            if (sinceStart >= 30) {
                rescanDone = true;
                OD_LOG("[D3D9] rescan period (30s) complete — stopping module re-enumeration");
            }
        }

        nidx9::MaybeLogStats();
        d3dx::MaybeLogStats();
        d3dx::MaybeLogCallerHistograms();
        d3d9vt::MaybeLogStats();
        mirror::MaybeLogStats();
        profiler::MaybeLogStats();
        sleepprof::MaybeLogStats();
        waitprof::MaybeLogStats();
        vkq::MaybeLogStats();
        resmirror::MaybeLogStats();
        pipeline::MaybeLogStats();
        readprofiler::MaybeLogStats();
        renderpool::MaybeLogStats();
        // Fires exactly once, ~60s after install — by then the bulk of
        // shaders have been captured. Reports SM distribution + opcode
        // histogram so we know exactly which D3D9 opcodes the upcoming
        // DXBC->SPIR-V translator must support.
        dxbc::MaybeRun();
        Sleep(250);
    }
    renderpool::Shutdown();
    pipeline::Shutdown();
    resmirror::Shutdown();
    vkq::Shutdown();
    waitprof::Shutdown();
    sleepprof::Shutdown();
    profiler::Shutdown();
    crashdbg::Shutdown();
    OD_LOG("[EXIT] instrumentation worker exiting");
}

void RunSafely() {
    __try {
        OD_LOG("[BOOT] worker thread entered, sleeping 50ms before init");
        Sleep(50);

        if (kInstrumentationOnlyMode) {
            RunInstrumentationLoop();
            return;
        }

        // Legacy path: SDL+Vulkan visible window with frame-capture display.
        const bool ok = RunVulkanWindow(gShouldExit);
        if (ok) {
            OD_LOG("[EXIT] worker exiting cleanly");
        } else {
            OD_LOG("[EXIT] worker exiting after init failure (game continues)");
        }
    }
    __except (WorkerCrashFilter(GetExceptionInformation())) {
        // Unreachable — filter returns CONTINUE_SEARCH.
    }
}

}

DWORD WINAPI BootstrapThreadProc(LPVOID /*userData*/) {
    RunSafely();
    return 0;
}

}
