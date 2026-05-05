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

// Burst size. History (2026-05-05):
//   K=32: crashed on first drain (~100% race rate).
//   K=2 (no SEH):     crashed at burst-enable; no log (upstream SEH
//                     swallowed). Process died.
//   K=2 with __except: 24 worker AVs / 2163 drains = 1.1% race rate.
//                      Process survived but D3D9 device dropped due to
//                      cumulative half-written constants → red screen.
//                      Captured EIP=0x00CA1D70, ESI=dword_1BAE0A8+0x28.
//                      Fault is inside a helper called from sub_CB7E80,
//                      writing to the second D3D9 constants buffer.
//   K=1:  no concurrency, no race, no perf. STABLE.
//
// Reverting to K=1 as the shipping default. The diagnostic data needed
// for the fix has been captured; no benefit to keeping K=2 in the
// shipped binary while the fix is being designed (it just makes the
// game unplayable). Re-enable K>=2 only with a TLS-shadowed replacement
// of the racy helper in our .injsec segment.
constexpr int kBatchK = 1;

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
std::atomic<uint64_t> g_workerExceptions{0};
std::atomic<bool>     g_enabled{false};   // hooks inert until SetEnabled(true)

// Captured once on the first worker exception inside RunOne — gives us the
// crash address and registers even if no SetUnhandledExceptionFilter ever
// fires (because some upstream SEH handler catches it, or because the
// failure manifests as a hang instead of a fault). One snapshot is enough;
// after that the counters keep ticking but we don't overwrite the first.
struct ExceptionSnapshot {
    DWORD    code;
    DWORD    flags;
    void*    address;
    DWORD    eax, ebx, ecx, edx, esi, edi, ebp, esp, eip;
    void*    thisPtr;
    void*    arg;
    DWORD    tid;
};
ExceptionSnapshot g_firstException = {};
std::atomic<bool> g_firstExceptionCaptured{false};

bool g_installed = false;
std::chrono::steady_clock::time_point g_lastLog;

// Inner exception filter: capture the EXCEPTION_POINTERS and store one
// snapshot. Returns EXCEPTION_EXECUTE_HANDLER so the __except body runs
// (which silently absorbs the exception, preventing process death).
int CaptureWorkerException(EXCEPTION_POINTERS* info,
                           const QueueEntry* e) {
    g_workerExceptions.fetch_add(1, std::memory_order_relaxed);
    bool expected = false;
    if (g_firstExceptionCaptured.compare_exchange_strong(expected, true)) {
        ExceptionSnapshot& s = g_firstException;
        s.code    = info->ExceptionRecord->ExceptionCode;
        s.flags   = info->ExceptionRecord->ExceptionFlags;
        s.address = info->ExceptionRecord->ExceptionAddress;
        s.eax = info->ContextRecord->Eax;
        s.ebx = info->ContextRecord->Ebx;
        s.ecx = info->ContextRecord->Ecx;
        s.edx = info->ContextRecord->Edx;
        s.esi = info->ContextRecord->Esi;
        s.edi = info->ContextRecord->Edi;
        s.ebp = info->ContextRecord->Ebp;
        s.esp = info->ContextRecord->Esp;
        s.eip = info->ContextRecord->Eip;
        s.thisPtr = e->thisPtr;
        s.arg     = e->arg;
        s.tid     = GetCurrentThreadId();
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

void __cdecl RunOne(uint32_t i, void* userData) {
    auto* arr = static_cast<QueueEntry*>(userData);
    auto& e = arr[i];
    auto fn = reinterpret_cast<PFN_HotSub>(e.tramp);
    __try {
        fn(e.thisPtr, e.arg);
    } __except (CaptureWorkerException(GetExceptionInformation(), &e)) {
        // Silently absorbed. Worker returns normally; ParallelFor's
        // group counter ticks; render thread wakes from its wait. Game
        // continues with whatever state corruption the partial sub_CB7E80
        // left behind — likely visual glitch or downstream crash, but at
        // least we've logged the exception address. Better than a silent
        // hang.
    }
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
    if (!g_enabled.load(std::memory_order_relaxed)) return false;
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
    SetEnabled(false);
    Drain();
    MH_DisableHook(reinterpret_cast<LPVOID>(kVA_CB7E80));
    MH_DisableHook(reinterpret_cast<LPVOID>(kVA_CA2610));
    MH_RemoveHook (reinterpret_cast<LPVOID>(kVA_CB7E80));
    MH_RemoveHook (reinterpret_cast<LPVOID>(kVA_CA2610));
    g_installed = false;
}

void SetEnabled(bool enabled) {
    bool prev = g_enabled.exchange(enabled, std::memory_order_release);
    if (prev != enabled) {
        OD_LOG("[Burst] %s. Hooks were %s; now %s.",
               enabled ? "ENABLED" : "DISABLED",
               prev ? "active" : "passthrough",
               enabled ? "batching" : "passthrough");
    }
}

void MaybeLogStats() {
    if (!g_installed) return;
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - g_lastLog).count() < 5) {
        return;
    }
    g_lastLog = now;

    OD_LOG("[Burst] total=%llu batched=%llu drains=%llu passthrough=%llu "
           "exceptions=%llu K=%d renderTid=%lu queueDepth=%d",
           (unsigned long long)g_total.load(std::memory_order_relaxed),
           (unsigned long long)g_batched.load(std::memory_order_relaxed),
           (unsigned long long)g_drains.load(std::memory_order_relaxed),
           (unsigned long long)g_passthrough.load(std::memory_order_relaxed),
           (unsigned long long)g_workerExceptions.load(std::memory_order_relaxed),
           kBatchK,
           (unsigned long)g_renderTid.load(std::memory_order_relaxed),
           g_queueN);

    // If a worker has ever faulted, dump the first captured snapshot.
    // Throttled by g_firstExceptionCaptured flag — we only have one slot
    // and once filled it stays. (Subsequent exceptions still bump the
    // counter, just don't overwrite the registers.)
    if (g_firstExceptionCaptured.load(std::memory_order_acquire)) {
        const ExceptionSnapshot& s = g_firstException;
        OD_LOG("[Burst] FIRST WORKER EXCEPTION: code=0x%08lX addr=%p tid=%lu",
               (unsigned long)s.code, s.address, (unsigned long)s.tid);
        OD_LOG("[Burst]   EIP=0x%08lX ESP=0x%08lX EBP=0x%08lX",
               (unsigned long)s.eip, (unsigned long)s.esp, (unsigned long)s.ebp);
        OD_LOG("[Burst]   EAX=0x%08lX EBX=0x%08lX ECX=0x%08lX EDX=0x%08lX",
               (unsigned long)s.eax, (unsigned long)s.ebx,
               (unsigned long)s.ecx, (unsigned long)s.edx);
        OD_LOG("[Burst]   ESI=0x%08lX EDI=0x%08lX  this=%p arg=%p",
               (unsigned long)s.esi, (unsigned long)s.edi,
               s.thisPtr, s.arg);
    }
}

}  // namespace
