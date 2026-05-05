#include "SyncOffloadProof.h"
#include "RenderPoolPatch.h"
#include "DebugLogger.h"
#include "MinHook/MinHook.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>

namespace overdrive::syncproof {

namespace {

// sub_CB7E80(this, NiNode*) — __thiscall (callee cleans 4 bytes).
// On x86 MSVC, __fastcall(void* a, void* edx_dummy, void* b) is binary-
// compatible: ecx=a, edx ignored, [esp+4]=b, callee retn 4. So we declare
// the hook as __fastcall and let the compiler emit the right epilogue.
typedef void (__thiscall *PFN_HotSub)(void* thisPtr, void* arg);

constexpr uintptr_t kVA_CB7E80 = 0x00CB7E80;

void* g_tramp_CB7E80 = nullptr;

std::atomic<int>      g_oneInN{100};
std::atomic<uint64_t> g_total{0};
std::atomic<uint64_t> g_offloaded{0};
std::atomic<uint64_t> g_workerExec{0};
std::atomic<DWORD>    g_renderTid{0};

// Per-worker TID seen during offloads — proves the work ran on threads other
// than the render thread. 8 slots is more than enough (pool has 6 workers).
LONG          g_seenTids[8] = {};
volatile LONG g_seenTidCount = 0;

bool g_installed = false;
std::chrono::steady_clock::time_point g_lastLog;

struct OffloadCtx {
    void* tramp;
    void* thisPtr;
    void* arg;
};

void NoteWorkerTid() {
    const DWORD tid = GetCurrentThreadId();
    const LONG count = g_seenTidCount;
    for (LONG i = 0; i < count && i < 8; ++i) {
        if (g_seenTids[i] == (LONG)tid) return;
    }
    if (count >= 8) return;
    const LONG idx = InterlockedIncrement(&g_seenTidCount) - 1;
    if (idx < 8) g_seenTids[idx] = (LONG)tid;
}

// Body executed on a pool worker thread (one task per offload).
// The worker calls the trampoline (= original sub_CB7E80) which performs
// the per-object matrix-prep work that the render thread would have done.
void __cdecl WorkerRun(uint32_t /*taskIdx*/, void* userData) {
    NoteWorkerTid();
    auto* ctx = static_cast<OffloadCtx*>(userData);
    auto fn  = reinterpret_cast<PFN_HotSub>(ctx->tramp);
    fn(ctx->thisPtr, ctx->arg);
    g_workerExec.fetch_add(1, std::memory_order_relaxed);
}

// Hook for sub_CB7E80. Runs on the render thread.
void __fastcall Hooked_CB7E80(void* thisPtr, void* /*edx*/, void* arg) {
    // Latch the render thread's TID on first call so MaybeLogStats can
    // contrast against the worker TIDs.
    if (g_renderTid.load(std::memory_order_relaxed) == 0) {
        g_renderTid.store(GetCurrentThreadId(), std::memory_order_relaxed);
    }

    const uint64_t n = g_total.fetch_add(1, std::memory_order_relaxed);
    const int oneIn = g_oneInN.load(std::memory_order_relaxed);

    if (oneIn <= 1 || (n % static_cast<uint64_t>(oneIn)) == 0) {
        OffloadCtx ctx{ g_tramp_CB7E80, thisPtr, arg };
        if (overdrive::renderpool::RunParallel(1, &WorkerRun, &ctx)) {
            g_offloaded.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        // Pool not yet captured — fall through to inline.
    }

    auto fn = reinterpret_cast<PFN_HotSub>(g_tramp_CB7E80);
    fn(thisPtr, arg);
}

}  // namespace

bool Install() {
    if (g_installed) return true;

    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
        OD_LOG("[SyncProof] MH_Initialize failed: %d", (int)s);
        return false;
    }

    s = MH_CreateHook(reinterpret_cast<LPVOID>(kVA_CB7E80),
                      reinterpret_cast<LPVOID>(&Hooked_CB7E80),
                      &g_tramp_CB7E80);
    if (s != MH_OK) {
        OD_LOG("[SyncProof] CreateHook(sub_CB7E80 @ 0x%08X) failed: %d",
               (unsigned)kVA_CB7E80, (int)s);
        return false;
    }
    s = MH_EnableHook(reinterpret_cast<LPVOID>(kVA_CB7E80));
    if (s != MH_OK) {
        OD_LOG("[SyncProof] EnableHook(sub_CB7E80) failed: %d", (int)s);
        return false;
    }

    g_installed = true;
    g_lastLog = std::chrono::steady_clock::now();
    OD_LOG("[SyncProof] Installed. sub_CB7E80 hooked. 1-in-N=%d (offload "
           "1 of every N calls onto a pool worker, sync-wait). Watch the "
           "stats log: if 'workerTids' includes TIDs distinct from "
           "'renderTid' AND game keeps rendering, multi-core drawcalling "
           "is proven on real Skyrim render-prep work.",
           g_oneInN.load());
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook(reinterpret_cast<LPVOID>(kVA_CB7E80));
    MH_RemoveHook (reinterpret_cast<LPVOID>(kVA_CB7E80));
    g_installed = false;
}

void SetOneInN(int n) {
    if (n < 1) n = 1;
    g_oneInN.store(n, std::memory_order_relaxed);
    OD_LOG("[SyncProof] 1-in-N changed to %d", n);
}

void MaybeLogStats() {
    if (!g_installed) return;
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - g_lastLog).count() < 5) {
        return;
    }
    g_lastLog = now;

    const uint64_t total = g_total.load(std::memory_order_relaxed);
    const uint64_t off   = g_offloaded.load(std::memory_order_relaxed);
    const uint64_t wexec = g_workerExec.load(std::memory_order_relaxed);
    const DWORD    rtid  = g_renderTid.load(std::memory_order_relaxed);

    char tidstr[256];
    int pos = 0;
    LONG tidCount = g_seenTidCount;
    if (tidCount > 8) tidCount = 8;
    tidstr[0] = '\0';
    for (LONG i = 0; i < tidCount && pos < 240; ++i) {
        pos += wsprintfA(tidstr + pos, "%s%lu",
                         i ? "," : "", (unsigned long)g_seenTids[i]);
    }

    OD_LOG("[SyncProof] sub_CB7E80: total=%llu offloaded=%llu workerExec=%llu "
           "1inN=%d renderTid=%lu workerTids=[%s]",
           (unsigned long long)total,
           (unsigned long long)off,
           (unsigned long long)wexec,
           g_oneInN.load(std::memory_order_relaxed),
           (unsigned long)rtid,
           tidstr);
}

}  // namespace
