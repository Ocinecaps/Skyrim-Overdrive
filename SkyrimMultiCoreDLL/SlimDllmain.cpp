// =============================================================================
// SkyrimMultiCoreDLL — slim build of the multi-core thread pool foundation
// =============================================================================
//
// This DLL exists for one purpose: prove or disprove FPS impact of the
// thread-pool foundation WITHOUT the instrumentation overhead of the full
// SkyrimRenderOverdrive build. Everything that would skew an FPS measurement
// is stripped:
//
//   NOT INCLUDED here (compared to the full DLL):
//     - D3D9 hooks (Direct3DCreate9, CreateDevice, Present, vtable bulk)
//     - NiDX9 hot-sub thunks (record-and-replay path)
//     - D3DX SSE replacements (these ARE wins, but extracted to keep the
//       slim build focused on isolating the pool-foundation overhead)
//     - Vulkan command queue + offscreen target + drain threads
//     - Live shader translator (DXBC -> SPIR-V)
//     - ResourceMirror (every CreateXxx allocation tracked)
//     - All profilers (Sleep, Wait, EIP-sampling, ScenegraphProfiler)
//     - DxbcAnalyzer one-shot histogram pass
//     - CrashDebugger symbol table (7K function VAs)
//     - D3D9Mirror typed wrappers + dedup cache
//     - D3D9PipelineDispatcher
//     - Periodic 5s log spam from every subsystem
//
//   INCLUDED:
//     - DllMain that hooks sub_A5B050 (the pool factory)
//     - RenderPoolPatch (capture pool ptr, observer, RunParallel API,
//       self-test + scaling-test that fire ONCE then go silent)
//     - DebugLogger (one-shot logs only, written to a separate file so it
//       doesn't collide with the full DLL's log)
//     - MinHook (linked from the existing project's source files)
//
// Output filename: SkyrimMultiCoreOverdrive.dll
// Log file: <SkyrimDir>\skyrim_multicore.log
//
// Deployment: rename to SkyrimRenderOverdrive.dll OR re-run the patcher
// with this name as the load target. The PE patch is otherwise identical.

#include "../SkyrimRenderDLL/Globals.h"
#include "../SkyrimRenderDLL/DebugLogger.h"
#include "../SkyrimRenderDLL/RenderPoolPatch.h"
#include "../SkyrimRenderDLL/D3DXReplace.h"
#include "../SkyrimRenderDLL/SlimEipSampler.h"
#include "../SkyrimRenderDLL/BurstBatch.h"
#include "../SkyrimRenderDLL/CrashDebugger.h"

#include <windows.h>
#include <shlwapi.h>
#include <chrono>

namespace overdrive {

static std::string ResolveSkyrimDir() {
    char buf[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    PathRemoveFileSpecA(buf);
    return buf;
}

static void WriteLoadBeacon(DWORD reason, HMODULE hModule) {
    char hostExe[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, hostExe, MAX_PATH);
    PathRemoveFileSpecA(hostExe);

    char beaconPath[MAX_PATH] = {};
    wsprintfA(beaconPath, "%s\\skyrim_multicore_LOAD_BEACON.txt", hostExe);

    HANDLE h = CreateFileA(beaconPath, GENERIC_WRITE, FILE_SHARE_READ,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    char ourDll[MAX_PATH] = {};
    GetModuleFileNameA(hModule, ourDll, MAX_PATH);

    SYSTEMTIME st{};
    GetLocalTime(&st);

    char body[1024];
    int n = wsprintfA(body,
        "Slim multi-core DLL load beacon\r\n"
        "When     : %04d-%02d-%02d %02d:%02d:%02d\r\n"
        "Reason   : %lu  (1=PROCESS_ATTACH, 2=THREAD_ATTACH, 3=THREAD_DETACH, 0=PROCESS_DETACH)\r\n"
        "Pid/Tid  : %lu / %lu\r\n"
        "Host exe : %s\r\n"
        "Our DLL  : %s\r\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        reason,
        GetCurrentProcessId(), GetCurrentThreadId(),
        hostExe, ourDll);
    DWORD written = 0;
    WriteFile(h, body, n, &written, nullptr);
    CloseHandle(h);
}

// =============================================================================
// Slim worker thread — no SDL, no Vulkan, no profilers. Just pumps
// renderpool::MaybeLogStats so the observer + self-test + scaling-test fire,
// then goes silent (renderpool is in quiet mode so periodic logs suppressed).
// =============================================================================

static DWORD WINAPI SlimWorkerProc(LPVOID /*userData*/) {
    OD_LOG("[BOOT] slim worker thread entered tid=%lu, sleeping 50ms before init",
           GetCurrentThreadId());
    Sleep(50);

    // Quiet mode — suppress the renderpool's 5-second periodic log line.
    // Self-test + scaling-test still log once each (they're one-shot).
    overdrive::renderpool::SetQuietMode(true);

    OD_LOG("[BOOT] slim worker entered pump loop. Periodic stats suppressed; "
           "self-test + scaling-test will log once each, then silence.");

    while (!gShouldExit.load(std::memory_order_relaxed)) {
        overdrive::renderpool::MaybeLogStats();
        // D3DX caller histograms — Phase 3 target discovery. The dominant
        // return address per D3DX function is the Skyrim function calling
        // it in a hot loop, which is the parallelization target.
        overdrive::d3dx::MaybeLogCallerHistograms();
        // Burst-batched ParallelFor stats (K=2 diagnostic re-run).
        overdrive::burst::MaybeLogStats();
        Sleep(250);
    }

    overdrive::renderpool::Shutdown();
    OD_LOG("[EXIT] slim worker exiting cleanly");
    return 0;
}

}  // namespace overdrive

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*lpReserved*/) {
    using namespace overdrive;

    WriteLoadBeacon(reason, hModule);

    switch (reason) {
        case DLL_PROCESS_ATTACH: {
            DisableThreadLibraryCalls(hModule);
            gSkyrimDir = ResolveSkyrimDir();

            const std::string logPath = gSkyrimDir + "\\skyrim_multicore.log";
            InitLogger(logPath);
            OD_LOG("[BOOT] DllMain ATTACH (slim multi-core DLL) pid=%lu tid=%lu skyrimDir=%s",
                GetCurrentProcessId(), GetCurrentThreadId(), gSkyrimDir.c_str());
            OD_LOG("[BOOT] This is the SLIM DLL: only the multi-core thread-pool "
                   "foundation is active. No D3D9 hooks, no Vulkan, no profilers, "
                   "no instrumentation. Use this build for clean FPS comparisons "
                   "vs vanilla.");

            // Install the renderpool hook from DllMain so we catch sub_A5B050's
            // ctor at the earliest possible moment. MinHook calls under the
            // loader lock are safe (no LoadLibrary chains in MH_Initialize /
            // MH_CreateHook / MH_EnableHook).
            if (!renderpool::Install()) {
                OD_LOG("[BOOT] RenderPool install failed — slim DLL will still "
                       "load but multi-core foundation isn't available");
            }

            // D3DX SSE replacements + caller histograms. The replacements are
            // pure CPU wins (SSE vs Microsoft's reference impl). The caller
            // histograms identify the Skyrim functions calling D3DX heavily —
            // those are the Phase 3 ParallelFor targets.
            if (!d3dx::Install()) {
                OD_LOG("[BOOT] D3DX install failed (caller discovery + SSE "
                       "speedup unavailable; multi-core foundation still works)");
            }

            // Step 1 toward idle-work pivot: lightweight EIP sampler on
            // the render thread. Page-bucketed heatmap every 30s → tells
            // us where the render thread spends CPU during real gameplay
            // (including camera-turn).
            if (!slimeip::Install()) {
                OD_LOG("[BOOT] SlimEipSampler install failed");
            }

            // Diagnostic for the burst-batch re-attempt. CrashDebugger
            // installs an unhandled-exception filter that, on a fatal
            // exception, captures EIP/ESP/registers + walks the stack
            // symbolically (Windows DLLs via dbghelp PDBs, TESV.exe via
            // IDA-extracted symbol table) into skyrim_overdrive_crash.log.
            // Without this, a crash inside our hooked sub_CB7E80 leaves
            // no forensic trace — just a vanished process. With it, we
            // pinpoint exactly which instruction faulted and what state
            // it was in, which tells us what shared state races.
            if (!crashdbg::Install()) {
                OD_LOG("[BOOT] CrashDebugger install failed (no forensic "
                       "trace on crash)");
            }

            // Re-enable burst-batched ParallelFor over sub_CB7E80 +
            // sub_CA2610 with K=2 — minimum possible concurrency. Two
            // workers in flight at any moment instead of six. If the
            // race is rate-dependent we may run clean and ratchet up.
            // If we crash, CrashDebugger gives us the racy instruction.
            // Either outcome is actionable.
            if (!burst::Install()) {
                OD_LOG("[BOOT] BurstBatch install failed");
            }

            // Spawn the worker thread that pumps the observer + tests.
            HANDLE th = CreateThread(nullptr, 0, SlimWorkerProc, nullptr, 0, nullptr);
            if (!th) {
                OD_LOG("[BOOT] CreateThread failed, GetLastError=%lu", GetLastError());
            } else {
                CloseHandle(th);
                OD_LOG("[BOOT] slim worker thread dispatched");
            }
            break;
        }
        case DLL_PROCESS_DETACH: {
            OD_LOG("[BOOT] DllMain DETACH (slim) — signaling worker exit");
            gShouldExit.store(true, std::memory_order_relaxed);
            CloseLogger();
            break;
        }
    }
    return TRUE;
}
