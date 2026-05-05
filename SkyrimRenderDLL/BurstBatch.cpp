#include "BurstBatch.h"
#include "RenderPoolPatch.h"
#include "DebugLogger.h"
#include "MinHook/MinHook.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>

namespace overdrive::burst {

namespace {

// __thiscall: this in ECX, arg pushed; callee retn 4. MSVC's __fastcall on
// x86 with three params (a, edx, b) emits identical caller/callee code,
// so we declare hooks as __fastcall and let the compiler match the ABI.
typedef void (__thiscall *PFN_HotSub)(void* thisPtr, void* arg);

// Burst size. K=32 crashed the game on the first drain (2026-05-05) — true
// concurrent execution of sub_CB7E80 raced on shared scratch state inside
// the function. Reduced to K=2 for the diagnostic re-run: minimum possible
// concurrency (only two workers in flight at any moment), so if the race
// is rate-dependent it may run clean and let us ratchet up to find the
// threshold. If it still crashes, CrashDebugger captures the racy
// instruction's address and we know exactly where to fix.
constexpr int kBatchK = 2;

constexpr uintptr_t kVA_CB7E80 = 0x00CB7E80;
constexpr uintptr_t kVA_CA2610 = 0x00CA2610;

void* g_tramp_CB7E80 = nullptr;
void* g_tramp_CA2610 = nullptr;

struct QueueEntry {
    void* tramp;
    void* thisPtr;
    void* arg;
};

// Single global queue. Only the render thread reads/writes the slots and the
// counter (the thread check at hook entry filters every other thread to
// passthrough), so no lock is needed on the producer side. While ParallelFor
// is running, workers read their own indexed slot from the array — no shared
// writes — and the render thread is blocked at ParallelFor's wait, so the
// queue is stable for the duration of the burst.
QueueEntry g_queue[kBatchK];
int        g_queueN = 0;

std::atomic<DWORD>    g_renderTid{0};
std::atomic<uint64_t> g_total{0};
std::atomic<uint64_t> g_batched{0};
std::atomic<uint64_t> g_drains{0};
std::atomic<uint64_t> g_passthrough{0};

bool g_installed = false;
std::chrono::steady_clock::time_point g_lastLog;

void __cdecl RunOne(uint32_t i, void* userData) {
    auto* arr = static_cast<QueueEntry*>(userData);
    auto& e = arr[i];
    auto fn = reinterpret_cast<PFN_HotSub>(e.tramp);
    fn(e.thisPtr, e.arg);
}

void Drain() {
    if (g_queueN == 0) return;
    overdrive::renderpool::ParallelFor(
        0, static_cast<uint32_t>(g_queueN), &RunOne, g_queue);
    g_drains.fetch_add(1, std::memory_order_relaxed);
    g_queueN = 0;
}

inline DWORD GetOrLatchRenderTid(DWORD tid) {
    DWORD r = g_renderTid.load(std::memory_order_relaxed);
    if (r != 0) return r;
    DWORD expected = 0;
    g_renderTid.compare_exchange_strong(expected, tid);
    return g_renderTid.load(std::memory_order_relaxed);
}

inline bool ShouldBatch(DWORD tid) {
    return tid == GetOrLatchRenderTid(tid);
}

void __fastcall Hooked_CB7E80(void* thisPtr, void* /*edx*/, void* arg) {
    g_total.fetch_add(1, std::memory_order_relaxed);
    const DWORD tid = GetCurrentThreadId();
    if (!ShouldBatch(tid)) {
        g_passthrough.fetch_add(1, std::memory_order_relaxed);
        reinterpret_cast<PFN_HotSub>(g_tramp_CB7E80)(thisPtr, arg);
        return;
    }
    g_queue[g_queueN++] = { g_tramp_CB7E80, thisPtr, arg };
    g_batched.fetch_add(1, std::memory_order_relaxed);
    if (g_queueN >= kBatchK) Drain();
}

void __fastcall Hooked_CA2610(void* thisPtr, void* /*edx*/, void* arg) {
    g_total.fetch_add(1, std::memory_order_relaxed);
    const DWORD tid = GetCurrentThreadId();
    if (!ShouldBatch(tid)) {
        g_passthrough.fetch_add(1, std::memory_order_relaxed);
        reinterpret_cast<PFN_HotSub>(g_tramp_CA2610)(thisPtr, arg);
        return;
    }
    g_queue[g_queueN++] = { g_tramp_CA2610, thisPtr, arg };
    g_batched.fetch_add(1, std::memory_order_relaxed);
    if (g_queueN >= kBatchK) Drain();
}

}  // namespace

bool Install() {
    if (g_installed) return true;

    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
        OD_LOG("[Burst] MH_Initialize failed: %d", (int)s);
        return false;
    }

    s = MH_CreateHook(reinterpret_cast<LPVOID>(kVA_CB7E80),
                      reinterpret_cast<LPVOID>(&Hooked_CB7E80),
                      &g_tramp_CB7E80);
    if (s != MH_OK) {
        OD_LOG("[Burst] CreateHook(CB7E80 @ 0x%08X) failed: %d",
               (unsigned)kVA_CB7E80, (int)s);
        return false;
    }
    s = MH_CreateHook(reinterpret_cast<LPVOID>(kVA_CA2610),
                      reinterpret_cast<LPVOID>(&Hooked_CA2610),
                      &g_tramp_CA2610);
    if (s != MH_OK) {
        OD_LOG("[Burst] CreateHook(CA2610 @ 0x%08X) failed: %d",
               (unsigned)kVA_CA2610, (int)s);
        return false;
    }

    if (MH_EnableHook(reinterpret_cast<LPVOID>(kVA_CB7E80)) != MH_OK ||
        MH_EnableHook(reinterpret_cast<LPVOID>(kVA_CA2610)) != MH_OK) {
        OD_LOG("[Burst] EnableHook failed");
        return false;
    }

    g_installed = true;
    g_lastLog = std::chrono::steady_clock::now();
    OD_LOG("[Burst] Installed. K=%d. Hooked sub_CB7E80 + sub_CA2610. "
           "Render-thread-only batching; other threads pass through to "
           "originals (deadlock-proof on save / non-render code paths). "
           "Each burst fans out across all 6 pool workers via ParallelFor; "
           "render thread waits ONCE per burst, not per call.",
           kBatchK);
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    Drain();
    MH_DisableHook(reinterpret_cast<LPVOID>(kVA_CB7E80));
    MH_DisableHook(reinterpret_cast<LPVOID>(kVA_CA2610));
    MH_RemoveHook (reinterpret_cast<LPVOID>(kVA_CB7E80));
    MH_RemoveHook (reinterpret_cast<LPVOID>(kVA_CA2610));
    g_installed = false;
}

void MaybeLogStats() {
    if (!g_installed) return;
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - g_lastLog).count() < 5) {
        return;
    }
    g_lastLog = now;

    OD_LOG("[Burst] total=%llu batched=%llu drains=%llu passthrough=%llu "
           "K=%d renderTid=%lu queueDepth=%d",
           (unsigned long long)g_total.load(std::memory_order_relaxed),
           (unsigned long long)g_batched.load(std::memory_order_relaxed),
           (unsigned long long)g_drains.load(std::memory_order_relaxed),
           (unsigned long long)g_passthrough.load(std::memory_order_relaxed),
           kBatchK,
           (unsigned long)g_renderTid.load(std::memory_order_relaxed),
           g_queueN);
}

}  // namespace
