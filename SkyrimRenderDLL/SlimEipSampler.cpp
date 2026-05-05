#include "SlimEipSampler.h"
#include "D3DXReplace.h"
#include "DebugLogger.h"
#include "Globals.h"
#include "CrashDebugger.h"

#include <windows.h>
#include <psapi.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>

namespace overdrive::slimeip {

namespace {

// 4 KB pages → pageId = eip >> 12. 16 K-slot open-addressed hash. With ~1 MB
// of TESV.exe code at 100 Hz sampling for 30 seconds, peak unique pages is in
// the low thousands; 16 K slots gives plenty of headroom.
constexpr int kHashSlots = 16384;

struct PageSlot {
    uint32_t pageId;     // (eip >> 12) | 1, so 0 means empty
    uint64_t hits;
    uint32_t lastEip;    // most recently sampled EIP within the page
};

PageSlot g_hash[kHashSlots] = {};
std::atomic<uint64_t> g_totalSamples{0};
std::atomic<uint64_t> g_failedSamples{0};

HANDLE g_thread = nullptr;
HANDLE g_targetHandle = nullptr;       // render thread handle (SUSPEND/CONTEXT)
DWORD  g_targetTid = 0;
std::atomic<bool> g_stopRequested{false};

uint32_t g_tesvLo = 0;
uint32_t g_tesvHi = 0;

// First dump 30s after the render TID latches (gives time to leave the
// loading screen and reach actual gameplay).
std::chrono::steady_clock::time_point g_lastDump;
std::chrono::steady_clock::time_point g_renderTidLatchedAt;
bool g_renderTidEverSeen = false;

// Render-thread CPU% accounting. GetThreadTimes returns user+kernel CPU time
// for the thread; comparing the delta over a wall-clock window tells us
// whether the render thread is CPU-bound (close to 100%) or GPU-bound
// (significantly less). This is THE question for whether parallelism can
// help: a render thread that's 95% CPU-busy benefits massively from work
// migration; one that's 30% busy waiting on the GPU sees nothing.
ULARGE_INTEGER g_lastUser{};
ULARGE_INTEGER g_lastKernel{};
bool           g_haveLastSnap = false;

inline ULARGE_INTEGER ToULI(const FILETIME& ft) {
    ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    return u;
}

inline uint32_t MixPageId(uint32_t p) {
    p ^= p >> 16; p *= 0x7feb352d;
    p ^= p >> 15; p *= 0x846ca68b;
    p ^= p >> 16; return p;
}

inline void RecordPage(uint32_t eip) {
    const uint32_t pid = (eip >> 12) | 1;
    uint32_t slot = MixPageId(pid) & (kHashSlots - 1);
    for (int probe = 0; probe < 64; ++probe) {
        if (g_hash[slot].pageId == 0) {
            g_hash[slot].pageId  = pid;
            g_hash[slot].hits    = 1;
            g_hash[slot].lastEip = eip;
            return;
        }
        if (g_hash[slot].pageId == pid) {
            ++g_hash[slot].hits;
            g_hash[slot].lastEip = eip;
            return;
        }
        slot = (slot + 1) & (kHashSlots - 1);
    }
    // Probe overflow — drop. With 16K slots this should never trigger.
}

bool EnsureTargetHandle() {
    if (g_targetHandle) return true;
    DWORD tid = overdrive::d3dx::gRenderThreadId.load(std::memory_order_relaxed);
    if (tid == 0) return false;
    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                          THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!h) {
        OD_LOG("[SlimEIP] OpenThread(tid=%lu) failed: %lu", tid, GetLastError());
        return false;
    }
    g_targetTid    = tid;
    g_targetHandle = h;
    g_renderTidLatchedAt = std::chrono::steady_clock::now();
    g_lastDump           = g_renderTidLatchedAt;
    g_renderTidEverSeen  = true;
    OD_LOG("[SlimEIP] Tracking render thread tid=%lu. First page-histogram "
           "dump in 30s. Sampling at ~100 Hz.", tid);
    return true;
}

void Sample() {
    if (!g_targetHandle) return;
    DWORD susp = SuspendThread(g_targetHandle);
    if (susp == (DWORD)-1) {
        g_failedSamples.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;
    BOOL got = GetThreadContext(g_targetHandle, &ctx);
    DWORD eip = got ? ctx.Eip : 0;
    ResumeThread(g_targetHandle);

    if (!got || eip == 0) {
        g_failedSamples.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    RecordPage(eip);
    g_totalSamples.fetch_add(1, std::memory_order_relaxed);
}

void Dump() {
    // Snapshot + reset so each window covers a clean 30-second slice.
    PageSlot snap[kHashSlots];
    memcpy(snap, g_hash, sizeof(snap));
    memset(g_hash, 0, sizeof(g_hash));

    // Collect non-empty entries.
    PageSlot top[kHashSlots];
    int n = 0;
    uint64_t total = 0;
    for (int i = 0; i < kHashSlots; ++i) {
        if (snap[i].pageId != 0) {
            top[n++] = snap[i];
            total += snap[i].hits;
        }
    }
    if (n == 0 || total == 0) {
        OD_LOG("[SlimEIP] no samples this window (render thread idle? "
               "load screen? tid=%lu)", g_targetTid);
        return;
    }

    // Insertion-sort the top 20 (n is at most ~few thousand, only need top 20
    // — full sort wastes CPU. Selection insert is fine).
    constexpr int kTopN = 20;
    PageSlot best[kTopN] = {};
    int bestCount = 0;
    for (int i = 0; i < n; ++i) {
        const PageSlot& e = top[i];
        // Find insertion position.
        int pos = bestCount;
        for (int j = 0; j < bestCount; ++j) {
            if (e.hits > best[j].hits) { pos = j; break; }
        }
        if (pos < kTopN) {
            int copyEnd = (bestCount < kTopN) ? bestCount : (kTopN - 1);
            for (int j = copyEnd; j > pos; --j) best[j] = best[j-1];
            best[pos] = e;
            if (bestCount < kTopN) ++bestCount;
        }
    }

    // Render-thread CPU% over the window. ~30s wall, GetThreadTimes returns
    // 100ns ticks of CPU time consumed (user+kernel).
    {
        FILETIME crt, ext, kt, ut;
        if (GetThreadTimes(g_targetHandle, &crt, &ext, &kt, &ut)) {
            ULARGE_INTEGER u = ToULI(ut), k = ToULI(kt);
            if (g_haveLastSnap) {
                uint64_t cpuTicks = (u.QuadPart - g_lastUser.QuadPart)
                                  + (k.QuadPart - g_lastKernel.QuadPart);
                double cpuMs   = cpuTicks / 10000.0;          // 100ns → ms
                double wallMs  = 30000.0;                     // dump cadence
                double cpuPct  = 100.0 * cpuMs / wallMs;
                if (cpuPct > 100.0) cpuPct = 100.0;
                const char* verdict;
                if (cpuPct >= 90.0)      verdict = "CPU-BOUND   (parallelism would help a lot)";
                else if (cpuPct >= 70.0) verdict = "MIXED       (parallelism helps in spikes)";
                else if (cpuPct >= 40.0) verdict = "PARTLY GPU  (some headroom for parallelism)";
                else                     verdict = "GPU-BOUND   (parallelism won't help FPS — render thread is waiting)";
                OD_LOG("[SlimEIP] render-thread CPU%%: %.1f%% over ~30s  (%.1f ms CPU / %.0f ms wall)  → %s",
                       cpuPct, cpuMs, wallMs, verdict);
            }
            g_lastUser = u; g_lastKernel = k; g_haveLastSnap = true;
        }
    }

    OD_LOG("[SlimEIP] render-thread CPU heatmap: %d unique pages, %llu samples. "
           "Top %d:", n, (unsigned long long)total, bestCount);
    for (int i = 0; i < bestCount; ++i) {
        const uint32_t pageVa = best[i].pageId << 12;
        const uint64_t hits   = best[i].hits;
        const uint32_t eip    = best[i].lastEip;
        const double   pct    = (100.0 * (double)hits) / (double)total;

        if (pageVa >= g_tesvLo && pageVa < g_tesvHi) {
            // Resolve to nearest known TESV function via CrashDebugger's
            // IDA symbol table. Falls back to hex if not found.
            unsigned long off = 0;
            const char* sym = overdrive::crashdbg::ResolveTesvAddr(eip, &off);
            if (sym && sym[0] && sym[0] != '?') {
                OD_LOG("[SlimEIP]   #%-2d  TESV  hits=%llu  %.2f%%  eip=0x%08X  %s+0x%lX",
                       i + 1, (unsigned long long)hits, pct, eip, sym, off);
            } else {
                OD_LOG("[SlimEIP]   #%-2d  TESV  hits=%llu  %.2f%%  eip=0x%08X  page=0x%08X (no symbol)",
                       i + 1, (unsigned long long)hits, pct, eip, pageVa);
            }
        } else {
            // External module (driver / kernel32 / ntdll / d3d9 / ENB / ...).
            // We don't have symbols for these in the slim build, but a simple
            // address-range lookup tells us which module.
            const char* mod = "ext";
            // Common Windows-loaded modules — address ranges we've seen in
            // logs. Approximate; extends as we observe more.
            if (pageVa >= 0x77400000u && pageVa < 0x77800000u) mod = "ntdll";
            else if (pageVa >= 0x75400000u && pageVa < 0x75500000u) mod = "kernel32";
            else if (pageVa >= 0x6F400000u && pageVa < 0x6FC00000u) mod = "d3d9/d3dx";
            else if (pageVa >= 0x6D400000u && pageVa < 0x6D800000u) mod = "amdvk/driver";
            else if (pageVa >= 0x67D00000u && pageVa < 0x67E00000u) mod = "amdvk/driver";
            OD_LOG("[SlimEIP]   #%-2d  %-12s  hits=%llu  %.2f%%  eip=0x%08X",
                   i + 1, mod, (unsigned long long)hits, pct, eip);
        }
    }
}

DWORD WINAPI SamplerProc(LPVOID) {
    OD_LOG("[SlimEIP] sampler thread tid=%lu started, waiting for render TID...",
           GetCurrentThreadId());
    while (!gShouldExit.load(std::memory_order_relaxed) &&
           !g_stopRequested.load(std::memory_order_relaxed)) {
        if (!EnsureTargetHandle()) {
            Sleep(50);
            continue;
        }
        Sample();
        Sleep(10);  // ~100 Hz

        auto now = std::chrono::steady_clock::now();
        auto since = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - g_lastDump).count();
        if (since >= 30000) {
            g_lastDump = now;
            Dump();
        }
    }
    if (g_targetHandle) { CloseHandle(g_targetHandle); g_targetHandle = nullptr; }
    OD_LOG("[SlimEIP] sampler exit (totalSamples=%llu, failed=%llu)",
           (unsigned long long)g_totalSamples.load(),
           (unsigned long long)g_failedSamples.load());
    return 0;
}

}  // namespace

bool Install() {
    HMODULE hTesv = GetModuleHandleW(nullptr);
    if (hTesv) {
        MODULEINFO mi = {};
        if (GetModuleInformation(GetCurrentProcess(), hTesv, &mi, sizeof(mi))) {
            g_tesvLo = (uint32_t)(uintptr_t)mi.lpBaseOfDll;
            g_tesvHi = g_tesvLo + mi.SizeOfImage;
        }
    }
    if (g_tesvLo == 0) { g_tesvLo = 0x00400000; g_tesvHi = 0x02000000; }

    g_thread = CreateThread(nullptr, 0, SamplerProc, nullptr, 0, nullptr);
    if (!g_thread) {
        OD_LOG("[SlimEIP] CreateThread failed: %lu", GetLastError());
        return false;
    }
    SetThreadPriority(g_thread, THREAD_PRIORITY_BELOW_NORMAL);
    OD_LOG("[SlimEIP] Installed. Will sample render thread at 100 Hz once "
           "D3DXReplace latches the render TID. TESV range 0x%08X..0x%08X.",
           g_tesvLo, g_tesvHi);
    return true;
}

void Shutdown() {
    if (g_renderTidEverSeen) {
        OD_LOG("[SlimEIP] shutdown: emitting final heatmap");
        Dump();
    }
    g_stopRequested.store(true, std::memory_order_release);
    if (g_thread) {
        WaitForSingleObject(g_thread, 200);
        CloseHandle(g_thread);
        g_thread = nullptr;
    }
}

void MaybeLogStats() { /* sampler manages its own cadence */ }

}  // namespace
