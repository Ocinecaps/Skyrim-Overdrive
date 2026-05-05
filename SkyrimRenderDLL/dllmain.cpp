#include "Globals.h"
#include "DebugLogger.h"
#include "BootstrapThread.h"
#include "D3D9Hook.h"
#include "NiDX9Hooks.h"
#include "D3DXReplace.h"
#include "RenderPoolPatch.h"

#include <windows.h>
#include <shlwapi.h>

// =============================================================================
// JMC stub override — eliminate Just-My-Code instrumentation overhead
// =============================================================================
//
// Profiling on 2026-05-05 (per-thread Profiler split) showed the actual render
// thread spending **8.21% of CPU** in __CheckForDebuggerJustMyCode — the #1
// hottest function on the render thread. Confirmed via tlog inspection that
// /JMC- IS on the cl.exe command line and <SupportJustMyCode>false</…> is set
// in the vcxproj, but v145 still emits the JMC stubs anyway. Likely a v145
// regression with the property handling.
//
// Workaround: define our own __CheckForDebuggerJustMyCode as a no-op. The
// linker resolves symbols from .obj files BEFORE pulling them from CRT libs,
// so our definition wins. Each call site then traps to a one-instruction
// no-op (a return) instead of the CRT's "check JMC bit, raise SEH if set"
// stub. Saves ~8% of render-thread CPU.
//
// Signature notes: MSVC's __CheckForDebuggerJustMyCode takes a single arg
// (pointer to a per-line JMC flag byte) under cdecl. The arg is pushed by
// the caller; cdecl means caller cleans the stack so our no-op signature
// matters less, but matching the canonical signature avoids any surprise
// from /Gz or analyzer warnings. The stub is __cdecl + 1 arg + does nothing.
extern "C" void __cdecl __CheckForDebuggerJustMyCode(void* /*pdwJMC*/) {
    // Intentional no-op. See comment above.
}

namespace overdrive {

static std::string ResolveSkyrimDir() {
    char buf[MAX_PATH] = {};
    // GetModuleFileName(nullptr) returns the host process exe (TESV.exe), not us.
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    PathRemoveFileSpecA(buf);
    return buf;
}

// Earliest possible "I'm here" signal — uses only kernel32 file APIs, no CRT,
// no logger init, no allocator. If this file appears, we know the TLS callback
// fired and our DLL was successfully LoadLibrary'd, even if the formal logger
// later fails. Writes are best-effort and silently ignored on failure.
static void WriteLoadBeacon(DWORD reason, HMODULE hModule) {
    char hostExe[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, hostExe, MAX_PATH);
    PathRemoveFileSpecA(hostExe);

    char beaconPath[MAX_PATH] = {};
    wsprintfA(beaconPath, "%s\\skyrim_overdrive_LOAD_BEACON.txt", hostExe);

    HANDLE h = CreateFileA(beaconPath, GENERIC_WRITE, FILE_SHARE_READ,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    char ourDll[MAX_PATH] = {};
    GetModuleFileNameA(hModule, ourDll, MAX_PATH);

    SYSTEMTIME st{};
    GetLocalTime(&st);

    char body[1024];
    int n = wsprintfA(body,
        "DLL load beacon\r\n"
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

}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*lpReserved*/) {
    using namespace overdrive;

    // BEACON FIRST: prove load via raw Win32 even if everything below fails.
    WriteLoadBeacon(reason, hModule);

    switch (reason) {
        case DLL_PROCESS_ATTACH: {
            DisableThreadLibraryCalls(hModule);
            gSkyrimDir = ResolveSkyrimDir();

            const std::string logPath = gSkyrimDir + "\\skyrim_overdrive.log";
            InitLogger(logPath);
            OD_LOG("[BOOT] DllMain ATTACH pid=%lu tid=%lu skyrimDir=%s",
                GetCurrentProcessId(), GetCurrentThreadId(), gSkyrimDir.c_str());

            // Install D3D9 hooks BEFORE Skyrim's entry point runs (Direct3DCreate9
            // is called during render setup, which happens after our DllMain
            // returns). IAT manipulation does not load any modules so it is
            // safe under the loader lock.
            if (!d3d9hook::Install()) {
                OD_LOG("[BOOT] D3D9 hook install failed (game will still run, no frame capture)");
            }
            // Phase 3: pure-observation NiDX9 hot-function counters. Game
            // behavior unchanged. Stats logged every 5s by the worker thread.
            if (!nidx9::Install()) {
                OD_LOG("[BOOT] NiDX9 hook install failed (game will still run, no NiDX9 stats)");
            }
            // Phase 4 starter: replace D3DXMatrixMultiplyTranspose with our
            // SSE implementation. All three NiDX9 hot functions call into it,
            // so the replacement speeds up every transform path.
            if (!d3dx::Install()) {
                OD_LOG("[BOOT] D3DX replacement install failed (game will still run, "
                       "no Phase 4 SSE acceleration)");
            }
            // RenderPool patch: install hook on sub_A5B050 NOW under the
            // loader lock, alongside d3d9hook/nidx9/d3dx. This is the only
            // way to catch the pool ctor — it fires during TESV's early
            // init (sub_A59930 → sub_A5B050), well before our worker thread
            // gets a chance to install hooks. MinHook calls under loader
            // lock are safe (no LoadLibrary chains).
            if (!renderpool::Install()) {
                OD_LOG("[BOOT] RenderPool install failed (multi-core mod disabled, "
                       "but game runs)");
            }

            // CRITICAL: never do SDL/Vulkan init here. We hold the loader lock.
            // Hand work to a thread; return immediately.
            HANDLE th = CreateThread(nullptr, 0, BootstrapThreadProc, nullptr, 0, nullptr);
            if (!th) {
                OD_LOG("[BOOT] CreateThread failed, GetLastError=%lu", GetLastError());
            } else {
                CloseHandle(th);
                OD_LOG("[BOOT] worker thread dispatched");
            }
            break;
        }
        case DLL_PROCESS_DETACH: {
            OD_LOG("[BOOT] DllMain DETACH — signaling worker exit");
            gShouldExit.store(true, std::memory_order_relaxed);
            // Don't WaitForSingleObject here — we may be in process teardown
            // with the loader lock; the worker can race-finish on its own.
            CloseLogger();
            break;
        }
    }
    return TRUE;
}
