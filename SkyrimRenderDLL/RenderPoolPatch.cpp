#include "RenderPoolPatch.h"
#include "DebugLogger.h"
#include "MinHook/MinHook.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>

namespace overdrive::renderpool {

namespace {

// =============================================================================
// Pool struct offsets — see header for full layout description
// =============================================================================

constexpr size_t kOff_Vtable      = 0x000;
constexpr size_t kOff_WorkerSem   = 0x008;
constexpr size_t kOff_TaskCounter = 0x00C;
constexpr size_t kOff_WorkerCount = 0x018;
constexpr size_t kOff_ThreadCount = 0x01C;
constexpr size_t kOff_ThreadArr   = 0x020;
constexpr size_t kOff_Shutdown    = 0x050;
constexpr size_t kOff_CritSec     = 0x054;
constexpr size_t kOff_TaskQueue   = 0x06C;
constexpr size_t kOff_MasterSem   = 0x26C;
constexpr size_t kPoolStructEnd   = 0x280;
constexpr size_t kTaskQueueSlots  = 64;

// Vtable VAs from IDA disassembly. Pool uses 0x0110DC44 transiently during
// ctor, then writes 0x0110DD1C as the persistent vtable.
constexpr uintptr_t kExpectedVtable_PreInit  = 0x0110DC44;
constexpr uintptr_t kExpectedVtable_PostInit = 0x0110DD1C;

// Pool ctor address — sub_A5B050.
constexpr uintptr_t kVA_PoolCtor = 0x00A5B050;

// Worker count is hard-clamped to 6 in the ctor body. Use this as a
// secondary verification when memory-scanning.
constexpr uint32_t kExpectedWorkerCount = 6;

// =============================================================================
// Hook trampoline + naked detour
// =============================================================================
//
// sub_A5B050 is __thiscall(this, int) ending in `retn 4` (callee cleans the
// stack arg). __thiscall has no direct C++ syntax in MSVC for free functions,
// and __fastcall has different stack-cleanup semantics. The first build of
// this hook used a __fastcall detour that called the trampoline; that
// caused an ESP mismatch when we returned (we cleaned 0 bytes; Skyrim's
// caller expected 4 cleaned). /RTCs caught this as a runtime check failure.
//
// Fix: NAKED detour. We don't take any C++ args — we receive ECX directly
// from Skyrim's caller, capture it, then `jmp` straight into the trampoline.
// The trampoline runs the original prologue and jumps to mid-original; the
// original eventually does `retn 4` which is what Skyrim's caller expects.
// We never `ret`; ESP is preserved across the entire call as if our detour
// wasn't there.

// Trampoline pointer — used only via inline-asm `jmp` from the naked detour;
// no C++ signature attached because the detour bypasses C calling conventions.
void* g_origPoolCtor = nullptr;

// =============================================================================
// State (must be declared BEFORE CaptureThisPtr so it can reference them)
// =============================================================================

std::atomic<void*> g_pool{nullptr};
std::atomic<bool>  g_installed{false};
std::atomic<bool>  g_capturedViaHook{false};
std::atomic<bool>  g_capturedViaScan{false};
std::atomic<bool>  g_quiet{false};      // suppress periodic log lines (slim DLL)

// Passive observation stats.
std::atomic<uint32_t> g_observePolls{0};
std::atomic<uint32_t> g_observeNonEmpty{0};
std::atomic<uint32_t> g_observeTaskMaxSeen{0};

// Vtable observation buckets — see header (Phase 1 description).
constexpr size_t kVtableBuckets = 16;
struct VtableEntry {
    volatile uintptr_t vtablePtr;
    volatile uintptr_t slot0;
    volatile uintptr_t slot1;
    volatile uintptr_t slot2;
    volatile uintptr_t slot3;
    volatile LONG      hits;
};
VtableEntry g_vtables[kVtableBuckets] = {};

void NoteTaskVtable(uintptr_t vt, uintptr_t s0, uintptr_t s1, uintptr_t s2, uintptr_t s3) {
    for (size_t i = 0; i < kVtableBuckets; ++i) {
        const uintptr_t existing = g_vtables[i].vtablePtr;
        if (existing == vt) {
            InterlockedIncrement(&g_vtables[i].hits);
            return;
        }
        if (existing == 0) {
            const LONG prev = InterlockedCompareExchange(
                reinterpret_cast<volatile LONG*>(&g_vtables[i].vtablePtr),
                static_cast<LONG>(vt), 0);
            if (prev == 0) {
                g_vtables[i].slot0 = s0;
                g_vtables[i].slot1 = s1;
                g_vtables[i].slot2 = s2;
                g_vtables[i].slot3 = s3;
                InterlockedIncrement(&g_vtables[i].hits);
                return;
            }
            if ((uintptr_t)prev == vt) {
                InterlockedIncrement(&g_vtables[i].hits);
                return;
            }
        }
    }
}

// =============================================================================
// SEH-protected memory reads — used by both passive observer and scan fallback
// =============================================================================

bool SafeRead32(const void* addr, uint32_t* out) {
    __try {
        *out = *reinterpret_cast<const volatile uint32_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// =============================================================================
// Capture function (called by the naked detour via __cdecl)
// =============================================================================

void __cdecl CaptureThisPtr(void* thisPtr) {
    void* prior = nullptr;
    if (g_pool.compare_exchange_strong(prior, thisPtr, std::memory_order_acq_rel)) {
        g_capturedViaHook.store(true, std::memory_order_release);
        OD_LOG("[RenderPool] HOOK fired: pool ctor this=%p — captured", thisPtr);
    } else if (prior != thisPtr) {
        OD_LOG("[RenderPool] HOOK ctor#second thisPtr=%p (existing=%p)", thisPtr, prior);
    }
}

// =============================================================================
// Naked detour
// =============================================================================
//
// On entry, ECX holds `this` and the stack has [ret_to_skyrim, arg_0]. We:
//   1. Save ECX (callee-saved by us across the call to CaptureThisPtr)
//   2. Push ECX as cdecl arg → CaptureThisPtr(thisPtr)
//   3. Restore ESP and ECX
//   4. JMP to the trampoline (which IS the original's relocated prologue +
//      a jump back to mid-original)
//
// Net stack delta: zero. Net register delta: ECX preserved; CaptureThisPtr
// preserves EBX/ESI/EDI per cdecl callee-saved rules; EAX/EDX clobbered but
// they were caller-saved anyway. Skyrim's caller is unaware we ran.

__declspec(naked) void HookedPoolCtor_Naked() {
    __asm {
        push    ecx                     // save this
        push    ecx                     // arg = this (cdecl: pushed arg)
        call    CaptureThisPtr          // void __cdecl CaptureThisPtr(void*)
        add     esp, 4                  // cdecl: caller cleans the arg
        pop     ecx                     // restore this
        jmp     dword ptr [g_origPoolCtor]   // jump to trampoline (= original prologue)
    }
}

// =============================================================================
// Memory-scan fallback
// =============================================================================
//
// If the hook missed (sub_A5B050 fired during Skyrim's pre-DLL init), we walk
// committed-readable memory regions of the process and look for an object
// whose first DWORD is 0x0110DD1C (the post-init vtable). The pool is a
// singleton, but plenty of code might have 0x0110DD1C as a literal operand;
// we filter candidates by also checking +0x18 == 6 (worker count is clamped
// to 6 in the ctor).
//
// Walks all readable, committed memory in the lower 2 GB. TESV.exe is a
// 32-bit process; we cap at 0x80000000 to avoid kernel-reserved space.
//
// Bounded — first match wins. Runs once.

// Loose verify: the pool's only invariants we can rely on without timing
// assumptions are (1) vtable is one of two known constants and (2) workerCount
// at +0x18 is in [1..8] (the ctor clamps to 6, so values up to 6 are valid;
// we allow up to 8 in case a future Skyrim variant increases it). Other
// fields can transiently be zero during ctor, so we do NOT require them
// non-null — this is what made the strict verifier miss the pool last run.
bool VerifyCandidate(const void* candidate) {
    auto* base = reinterpret_cast<const uint8_t*>(candidate);
    uint32_t vt = 0, workerCount = 0;
    if (!SafeRead32(base + kOff_Vtable, &vt)) return false;
    if (vt != kExpectedVtable_PostInit && vt != kExpectedVtable_PreInit) return false;
    if (!SafeRead32(base + kOff_WorkerCount, &workerCount)) return false;
    if (workerCount < 1 || workerCount > 8) return false;
    return true;
}

void* ScanForPool() {
    OD_LOG("[RenderPool] Scan: walking memory for pool object (loose mode)...");
    auto* addr  = reinterpret_cast<uint8_t*>(0x00010000);
    auto* end   = reinterpret_cast<uint8_t*>(0x80000000);
    size_t regionsScanned = 0;
    size_t bytesScanned = 0;
    size_t vtableHits = 0;          // # of memory locations matching vtable
    size_t verifyPassed = 0;        // # that also passed worker-count check
    constexpr size_t kMaxLoggedHits = 8;
    size_t logged = 0;
    void* firstVerified = nullptr;

    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) break;
        const auto* regionBase = reinterpret_cast<uint8_t*>(mbi.BaseAddress);
        size_t regionSize = mbi.RegionSize;
        uint8_t* nextAddr = const_cast<uint8_t*>(regionBase) + regionSize;

        const bool committed = (mbi.State == MEM_COMMIT);
        const bool readable  = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                                               PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                               PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
        const bool guard = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;

        if (committed && readable && !guard) {
            ++regionsScanned;
            bytesScanned += regionSize;
            // SCAN EVERYTHING, INCLUDING MEM_IMAGE — the pool object could
            // be a global in TESV's BSS (writable .data section). Previous
            // build skipped MEM_IMAGE and that's the most likely reason it
            // missed. Code regions also have many false positives where
            // 0x0110DD1C appears as an immediate operand, but VerifyCandidate
            // filters those by checking +0x18 == valid worker count.
            const auto* p   = reinterpret_cast<const uint32_t*>(regionBase);
            const auto* pE  = reinterpret_cast<const uint32_t*>(regionBase + regionSize);
            // Keep room for the full struct read in VerifyCandidate.
            for (; p + (kPoolStructEnd / 4) < pE; ++p) {
                uint32_t v = 0;
                if (!SafeRead32(p, &v)) break;
                if (v != kExpectedVtable_PostInit && v != kExpectedVtable_PreInit) continue;
                ++vtableHits;
                if (logged < kMaxLoggedHits) {
                    uint32_t wc = 0, ws = 0, ms = 0;
                    SafeRead32(reinterpret_cast<const uint8_t*>(p) + kOff_WorkerCount, &wc);
                    SafeRead32(reinterpret_cast<const uint8_t*>(p) + kOff_WorkerSem,   &ws);
                    SafeRead32(reinterpret_cast<const uint8_t*>(p) + kOff_MasterSem,   &ms);
                    OD_LOG("[RenderPool] Scan: vtable match at %p vt=0x%08X workerCount=%u "
                           "workerSem=0x%08X masterSem=0x%08X mem.Type=%lu",
                           (void*)p, v, wc, ws, ms, mbi.Type);
                    ++logged;
                }
                if (VerifyCandidate(p)) {
                    ++verifyPassed;
                    if (!firstVerified) firstVerified = const_cast<uint32_t*>(p);
                }
            }
        }
        if (nextAddr <= addr) break;
        addr = nextAddr;
    }
    OD_LOG("[RenderPool] Scan: complete. Regions=%zu bytes=%zu vtableHits=%zu verifyPassed=%zu",
           regionsScanned, bytesScanned, vtableHits, verifyPassed);
    return firstVerified;
}

std::atomic<int> g_scanAttempts{0};
constexpr int kMaxScanAttempts = 6;     // retry up to 6 times across ~30s

void TryMemoryScanFallback() {
    if (g_pool.load(std::memory_order_acquire)) return;
    if (g_capturedViaScan.load(std::memory_order_acquire)) return;
    int attempt = g_scanAttempts.fetch_add(1, std::memory_order_acq_rel) + 1;
    OD_LOG("[RenderPool] Scan attempt %d/%d", attempt, kMaxScanAttempts);
    void* p = ScanForPool();
    if (!p) return;
    void* prior = nullptr;
    if (g_pool.compare_exchange_strong(prior, p, std::memory_order_acq_rel)) {
        g_capturedViaScan.store(true, std::memory_order_release);
        OD_LOG("[RenderPool] Captured pool via memory-scan fallback: pool=%p", p);
    }
}

// =============================================================================
// Passive observer
// =============================================================================

void DoObserveTick() {
    void* pool = g_pool.load(std::memory_order_acquire);
    if (!pool) return;

    g_observePolls.fetch_add(1, std::memory_order_relaxed);

    auto* base = reinterpret_cast<uint8_t*>(pool);
    const auto* slots = reinterpret_cast<const volatile uintptr_t*>(base + kOff_TaskQueue);

    uint32_t filled = 0;
    for (size_t i = 0; i < kTaskQueueSlots; ++i) {
        uintptr_t taskPtr = slots[i];
        if (taskPtr == 0) continue;
        ++filled;

        uint32_t vtPtr = 0;
        if (!SafeRead32(reinterpret_cast<const void*>(taskPtr), &vtPtr)) continue;
        if (vtPtr == 0) continue;
        uint32_t s0=0, s1=0, s2=0, s3=0;
        const uint32_t* vt = reinterpret_cast<const uint32_t*>(vtPtr);
        if (!SafeRead32(vt + 0, &s0)) continue;
        SafeRead32(vt + 1, &s1);
        SafeRead32(vt + 2, &s2);
        SafeRead32(vt + 3, &s3);
        NoteTaskVtable(vtPtr, s0, s1, s2, s3);
    }
    if (filled > g_observeTaskMaxSeen.load(std::memory_order_relaxed)) {
        g_observeTaskMaxSeen.store(filled, std::memory_order_relaxed);
    }
    if (filled > 0) g_observeNonEmpty.fetch_add(1, std::memory_order_relaxed);
}

// =============================================================================
// Wake-pool — release workerSem so the master thread runs ResumeThread on workers
// =============================================================================
//
// 2026-05-05 IDA finding: workers are spawned with dwCreationFlags=4
// (CREATE_SUSPENDED) by the ctor at sub_A5B050. The master thread sub_A5AC30
// runs:
//   WaitForSingleObject(pool->workerSem [+0x8], INFINITE);
//   for (i = 0; i < workerCount; ++i) ResumeThread(workerHandles[i]);
//   ExitThread(0);
//
// Skyrim's own code never releases workerSem (no caller of sub_A5AD60 either).
// The pool is vestigial: ctor builds the apparatus, but nothing wakes the
// master. Workers stay suspended forever → masterSem never gets a worker
// blocked on it → our ReleaseSemaphore(masterSem) just accumulates permits
// no one consumes → tasks queue indefinitely with no execution.
//
// We release workerSem ourselves. Master wakes, ResumeThread's all 6 workers,
// exits. Workers enter sub_A5B000 → sub_A59750 init → loop calling sub_A5AE90
// (which is what consumes our masterSem permits and runs our tasks).
//
// Safety: Idempotent. If someone already released workerSem (master has
// already run + exited), our ReleaseSemaphore puts a permit on a dead
// semaphore — harmless leak. ResumeThread on already-resumed threads is also
// safe (returns prev suspend count, no double-resume hazard since Windows
// counts down the per-thread suspend count and won't go below 0).

std::atomic<bool> g_poolWoken{false};

void WakePoolIfDormant() {
    if (g_poolWoken.exchange(true, std::memory_order_acq_rel)) return;

    void* pool = g_pool.load(std::memory_order_acquire);
    if (!pool) {
        OD_LOG("[RenderPool] Wake: skipped — pool not captured yet");
        g_poolWoken.store(false, std::memory_order_release);  // allow retry
        return;
    }

    // Verify pool is post-init (vtable == off_110DD1C). If still pre-init,
    // ctor hasn't finished — wait. WaitForSingleObject below is on the
    // workerSem handle which the ctor sets up early, so technically we could
    // race here, but better to be safe.
    uint32_t vt = 0;
    if (!SafeRead32(pool, &vt) || vt != kExpectedVtable_PostInit) {
        OD_LOG("[RenderPool] Wake: skipped — pool vtable=0x%08X (not post-init 0x%08X yet)",
               vt, (unsigned)kExpectedVtable_PostInit);
        g_poolWoken.store(false, std::memory_order_release);  // allow retry
        return;
    }

    HANDLE workerSem = nullptr;
    if (!SafeRead32(reinterpret_cast<uint8_t*>(pool) + kOff_WorkerSem,
                    reinterpret_cast<uint32_t*>(&workerSem)) || !workerSem) {
        OD_LOG("[RenderPool] Wake: skipped — workerSem handle unreadable");
        return;
    }

    // Probe: is the master thread STILL waiting (i.e., are workers still
    // suspended)? We can tell indirectly by reading [+0x0C] — master decrements
    // it after WaitForSingleObject succeeds. If [+0x0C] is still 1, master
    // hasn't run yet. If 0, master has run and our wake is a no-op (still
    // safe).
    uint32_t taskCounter = 0;
    SafeRead32(reinterpret_cast<uint8_t*>(pool) + kOff_TaskCounter, &taskCounter);

    LONG prevCount = 0;
    BOOL ok = ReleaseSemaphore(workerSem, 1, &prevCount);
    if (!ok) {
        DWORD err = GetLastError();
        OD_LOG("[RenderPool] Wake: ReleaseSemaphore(workerSem=%p) failed err=%lu — "
               "either bad handle or max-count exceeded (already permits in flight)",
               workerSem, err);
        return;
    }

    OD_LOG("[RenderPool] Wake: ReleaseSemaphore(workerSem=%p) OK prevCount=%ld "
           "pool[+0x0C]=%u (1=master still waiting, 0=master already ran). "
           "If master was waiting, all 6 CREATE_SUSPENDED workers are now resumed "
           "and looping in sub_A5B000.",
           workerSem, (long)prevCount, taskCounter);
}

std::atomic<bool> g_verifiedVtable{false};
void MaybeVerifyPool() {
    if (g_verifiedVtable.load(std::memory_order_acquire)) return;
    void* pool = g_pool.load(std::memory_order_acquire);
    if (!pool) return;
    uint32_t vt = 0;
    if (!SafeRead32(pool, &vt)) return;
    if (vt == 0) return;
    bool ok = (vt == kExpectedVtable_PreInit) || (vt == kExpectedVtable_PostInit);
    OD_LOG("[RenderPool] Pool vtable verify: pool=%p vtable=0x%08X expected=0x%08X/0x%08X %s "
           "(via %s)",
           pool, vt,
           (unsigned)kExpectedVtable_PreInit, (unsigned)kExpectedVtable_PostInit,
           ok ? "OK" : "MISMATCH",
           g_capturedViaHook ? "hook" : "scan");
    if (ok) {
        uint32_t workerSem=0, masterSem=0, workerCount=0, shutdownByte=0;
        SafeRead32(reinterpret_cast<uint8_t*>(pool) + kOff_WorkerSem, &workerSem);
        SafeRead32(reinterpret_cast<uint8_t*>(pool) + kOff_MasterSem, &masterSem);
        SafeRead32(reinterpret_cast<uint8_t*>(pool) + kOff_WorkerCount, &workerCount);
        SafeRead32(reinterpret_cast<uint8_t*>(pool) + kOff_Shutdown, &shutdownByte);
        OD_LOG("[RenderPool] Pool struct: workerSem=0x%08X masterSem=0x%08X "
               "workerCount=%u shutdownByte=0x%02X",
               workerSem, masterSem, workerCount, shutdownByte & 0xFF);
    }
    g_verifiedVtable.store(true, std::memory_order_release);
}

// =============================================================================
// Phase 2: Submit / RunParallel — feed our own tasks into Skyrim's pool
// =============================================================================
//
// Task / group struct shapes are binary-compatible with Skyrim's own tasks
// (decoded from sub_A5AE90 disasm). The worker reads:
//   task->vtable[2](task)   for Run
//   task->vtable[3](task)   for Finish
//   task->[+0x4]            requeue flag (we set 0)
//   task->[+0x8]            group pointer
//   task->[+0xC]            skip-Validate flag (we set 0 → skip Validate)
//   task->[+0x14]           next-task in slot's linked list
// Worker reads from group:
//   group->[+0x8]           HANDLE sem (released when counter reaches target)
//   group->[+0xC]           CRITICAL_SECTION (locked around counter inc)
//   group->[+0x25]          flag (0 = enable release on counter==target)
//   group->[+0x26]          flag (0 = run normally; non-zero skips Run/Validate)
//   group->[+0x2C]          target count
//   group->[+0x30]          counter (incremented after each task's Finish)
//
// Beyond +0x14, the task struct is OUR scratch space — Skyrim never reads
// past there. We stash the user's run function + index + userData pointer
// at +0x18..+0x23.

#pragma pack(push, 4)
struct OdTaskGroup {
    void*            vtable;            // +0x00 — unused by worker; we leave nullptr
    uint32_t         field4;             // +0x04 — unused
    HANDLE           sem;                // +0x08 — released when counter == target
    CRITICAL_SECTION cs;                 // +0x0C — 0x18 bytes
    uint8_t          flag24;             // +0x24 — padding/unused
    uint8_t          flag25;             // +0x25 — 0 means "complete normally"
    uint8_t          flag26;             // +0x26 — 0 means "run tasks normally"
    uint8_t          flag27;             // +0x27 — padding/unused
    uint32_t         field28;            // +0x28
    uint32_t         target;             // +0x2C — expected #completions
    volatile LONG    counter;            // +0x30 — incremented per finished task
    uint32_t         field34;            // +0x34
    uint32_t         field38;            // +0x38
    uint32_t         field3C;            // +0x3C
};
static_assert(sizeof(OdTaskGroup) == 0x40, "OdTaskGroup layout drift");

struct OdTask {
    void**   vtable;                     // +0x00 — points at g_OdTaskVtable
    uint8_t  requeueFlag;                // +0x04
    uint8_t  pad1[3];
    OdTaskGroup* group;                  // +0x08
    uint8_t  skipValidate;               // +0x0C — 0 to skip Validate, run directly
    uint8_t  pad2[3];
    void*    field10;                    // +0x10
    OdTask*  next;                       // +0x14 — intra-slot linked list
    // Our scratch area (Skyrim never reads past +0x14):
    void   (*runFn)(uint32_t, void*);    // +0x18
    uint32_t taskIdx;                    // +0x1C
    void*    userData;                   // +0x20
};
static_assert(sizeof(OdTask) == 0x24, "OdTask layout drift");
#pragma pack(pop)

// =============================================================================
// Vtable — 4 entries. Worker only calls slots 1, 2, 3. Slot 0 (dtor) is
// never invoked by sub_A5AE90 but we provide a no-op to be safe.
// =============================================================================
//
// Calling convention: __thiscall — `this` in ECX, no stack args, callee
// returns with `ret` (no cleanup). MSVC's __fastcall is binary-compatible
// for 0-arg "member" methods (both place `this` in ECX, neither touches
// stack args, both return with plain `ret`). EDX is unused/clobbered;
// safe to declare as a second arg we ignore.

void __fastcall OdTask_Dtor(OdTask* /*self*/, void* /*edx*/) {
    // No-op. Lifetime is owned by RunParallel's stack/calloc; we free in
    // the caller after WaitForSingleObject returns.
}

bool __fastcall OdTask_Validate(OdTask* /*self*/, void* /*edx*/) {
    // Worker only calls Validate when task->skipValidate (+0xC) != 0. We
    // set skipValidate = 0 in CreateTask, so this never runs. Return true
    // anyway in case some Skyrim path triggers it.
    return true;
}

void __fastcall OdTask_Run(OdTask* self, void* /*edx*/) {
    if (self && self->runFn) {
        self->runFn(self->taskIdx, self->userData);
    }
}

void __fastcall OdTask_Finish(OdTask* /*self*/, void* /*edx*/) {
    // No-op. After Finish, the worker zeroes task->[+0x8] and task->[+0x10],
    // increments group->counter, and may release group->sem.
}

void* g_OdTaskVtable[4] = {
    reinterpret_cast<void*>(&OdTask_Dtor),
    reinterpret_cast<void*>(&OdTask_Validate),
    reinterpret_cast<void*>(&OdTask_Run),
    reinterpret_cast<void*>(&OdTask_Finish),
};

// =============================================================================
// Submit — append task into pool's queue and wake a worker
// =============================================================================
//
// Locks pool->cs at +0x54, places task at the head of slot 0's linked list,
// unlocks, releases pool->masterSem at +0x26C. Worker in sub_A5AE90 wakes
// from the WaitForSingleObject, scans slots, takes our task.
//
// Slot selection: we always use slot 0 for now. Skyrim's enqueue function
// (which we haven't disassembled yet) probably hashes by some criterion to
// distribute load — but the worker just scans 0..63 for the first non-null,
// so single-slot use is correct, just suboptimal under heavy submission.

bool SubmitTask(OdTask* task) {
    void* pool_v = g_pool.load(std::memory_order_acquire);
    if (!pool_v || !task) return false;
    auto* poolBytes = reinterpret_cast<uint8_t*>(pool_v);

    auto* cs        = reinterpret_cast<CRITICAL_SECTION*>(poolBytes + kOff_CritSec);
    auto* slots     = reinterpret_cast<OdTask**>(poolBytes + kOff_TaskQueue);
    HANDLE masterSem = *reinterpret_cast<HANDLE*>(poolBytes + kOff_MasterSem);

    EnterCriticalSection(cs);
    task->next = slots[0];               // splice into slot 0's linked list
    slots[0]   = task;
    LeaveCriticalSection(cs);

    ReleaseSemaphore(masterSem, 1, nullptr);
    return true;
}

// =============================================================================
// Self-test — submit N no-op tasks, verify all ran
// =============================================================================
//
// Runs once after we've observed at least one Skyrim task in the queue (so
// we know the pool is fully alive and processing). If RunParallel returns
// with the counter at the expected value, our enqueue ABI matches Skyrim's
// — the multi-core mod's foundation is proven and Phase 3 (real workload
// patches) can build on it.

std::atomic<uint32_t> g_selfTestCounter{0};
std::atomic<bool>     g_selfTestRan{false};

void SelfTestTask(uint32_t /*taskIdx*/, void* /*userData*/) {
    g_selfTestCounter.fetch_add(1, std::memory_order_relaxed);
}

void RunSelfTestOnce() {
    if (g_selfTestRan.exchange(true, std::memory_order_acq_rel)) return;
    constexpr uint32_t kN = 6;
    g_selfTestCounter.store(0, std::memory_order_release);
    OD_LOG("[RenderPool] Self-test: submitting %u no-op tasks to Skyrim's pool...", kN);
    auto t0 = std::chrono::steady_clock::now();
    bool ok = overdrive::renderpool::RunParallel(kN, SelfTestTask, nullptr);
    auto t1 = std::chrono::steady_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    uint32_t got = g_selfTestCounter.load(std::memory_order_acquire);
    OD_LOG("[RenderPool] Self-test: ok=%d counter=%u/%u elapsed=%lldus -> %s",
           (int)ok, got, kN, (long long)us,
           (ok && got == kN) ? "PASS — Phase 2 enqueue ABI verified" :
           (got > 0)         ? "PARTIAL — some tasks ran, ABI mostly OK" :
                               "FAIL — no tasks ran (enqueue protocol wrong)");
}

// =============================================================================
// Scaling test — actual measurement that workers run on separate cores
// =============================================================================
//
// The self-test above proves we can SUBMIT, but the no-op tasks finish too
// fast to tell whether they ran in parallel or were serialized. The scaling
// test does substantial CPU work per task and measures elapsed time:
//
//   T_solo   = time to run 1 task with kIterations of integer hashing
//   T_par6   = time to run 6 tasks (each with kIterations) via RunParallel(6)
//   speedup  = (T_solo * 6) / T_par6
//
// On a system where Skyrim's 6 workers truly run on separate cores, speedup
// approaches 6.0. With dispatch overhead and any other CPU contention, real
// numbers tend to be 4.5-5.8x. Anything above 2x confirms genuine parallel
// execution; anything near 1x means the workers are serializing somehow.
//
// This is a real measurement, run once at session start. The result lands
// in the log as a single line stating the achieved speedup.

struct ScalingData {
    uint32_t              iterations;
    std::atomic<uint64_t> sums[8];        // up to 6 + headroom
};

void ScalingTask(uint32_t taskIdx, void* userData) {
    auto* d = static_cast<ScalingData*>(userData);
    // Integer hash mixing — entirely CPU-bound, no shared mutable state
    // beyond the per-task atomic sum slot (each task writes to a distinct
    // index, so no contention).
    uint64_t sum = 0;
    uint32_t state = (taskIdx + 1) * 0x9E3779B9u;
    for (uint32_t i = 0; i < d->iterations; ++i) {
        // xorshift32 + multiply
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state *= 1597334677u;
        sum += state;
    }
    d->sums[taskIdx].store(sum, std::memory_order_relaxed);
}

std::atomic<bool> g_scalingTestRan{false};

void RunScalingTestOnce() {
    if (g_scalingTestRan.exchange(true, std::memory_order_acq_rel)) return;

    // Pick iterations to give roughly 30-50ms per task on a modern CPU. That's
    // long enough to dwarf RunParallel's ~1ms submission overhead while short
    // enough that the test as a whole completes well under 300ms.
    constexpr uint32_t kIters = 25'000'000;

    ScalingData data{};
    data.iterations = kIters;

    OD_LOG("[RenderPool] Scaling test: warming up + measuring solo task...");
    // Warmup pass — first run sometimes pays for translation cache priming.
    overdrive::renderpool::RunParallel(1, ScalingTask, &data);

    auto t0 = std::chrono::steady_clock::now();
    overdrive::renderpool::RunParallel(1, ScalingTask, &data);
    auto t1 = std::chrono::steady_clock::now();
    auto solo_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();

    OD_LOG("[RenderPool] Scaling test: measuring 6 tasks in parallel...");
    auto t2 = std::chrono::steady_clock::now();
    overdrive::renderpool::RunParallel(6, ScalingTask, &data);
    auto t3 = std::chrono::steady_clock::now();
    auto par_us = std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count();

    double speedup = (par_us > 0) ? (double)(solo_us * 6) / (double)par_us : 0.0;
    const char* verdict =
        speedup >= 5.0 ? "EXCELLENT (real 6-core parallelism)" :
        speedup >= 4.0 ? "GOOD (workers on different cores)" :
        speedup >= 2.5 ? "PARTIAL (some parallelism, possibly contended cores)" :
        speedup >= 1.5 ? "WEAK (workers contending for cores)" :
                         "NO SCALING (workers serialized — investigation needed)";
    OD_LOG("[RenderPool] Scaling: solo=%lldus parallel6=%lldus speedup=%.2fx (ideal=6.00x) "
           "-> %s",
           (long long)solo_us, (long long)par_us, speedup, verdict);
}

std::chrono::steady_clock::time_point g_lastLog;
std::chrono::steady_clock::time_point g_installTime;
std::chrono::steady_clock::time_point g_lastScanAttempt;

}  // namespace

// =============================================================================
// Public RunParallel — outside the anon namespace so it has external linkage
// matching the header. Implementation just allocates group + tasks, submits,
// waits.
// =============================================================================

bool RunParallel(uint32_t numTasks,
                 void (*fn)(uint32_t, void*),
                 void* userData) {
    if (numTasks == 0 || !fn) return false;
    if (!g_pool.load(std::memory_order_acquire)) return false;

    // Group on heap (CRITICAL_SECTION must outlive any potential debugger
    // probe, plus we want stable address while workers reference it).
    auto* group = static_cast<OdTaskGroup*>(std::calloc(1, sizeof(OdTaskGroup)));
    if (!group) return false;
    InitializeCriticalSection(&group->cs);
    group->sem    = CreateSemaphoreA(nullptr, 0, 0x7FFFFFFF, nullptr);
    group->target = numTasks;
    group->counter = 0;
    group->flag25 = 0;
    group->flag26 = 0;
    if (!group->sem) {
        DeleteCriticalSection(&group->cs);
        std::free(group);
        return false;
    }

    auto* tasks = static_cast<OdTask*>(std::calloc(numTasks, sizeof(OdTask)));
    if (!tasks) {
        CloseHandle(group->sem);
        DeleteCriticalSection(&group->cs);
        std::free(group);
        return false;
    }

    for (uint32_t i = 0; i < numTasks; ++i) {
        tasks[i].vtable       = g_OdTaskVtable;
        tasks[i].requeueFlag  = 0;
        tasks[i].group        = group;
        tasks[i].skipValidate = 0;        // 0 means worker SKIPS Validate, runs Run directly
        tasks[i].field10      = nullptr;
        tasks[i].next         = nullptr;
        tasks[i].runFn        = fn;
        tasks[i].taskIdx      = i;
        tasks[i].userData     = userData;
    }

    // Submit all tasks. Each Submit takes the pool CS briefly. Since our
    // tasks all go into slot 0 (chained via task->next), the worker drains
    // them one at a time as it scans.
    for (uint32_t i = 0; i < numTasks; ++i) {
        SubmitTask(&tasks[i]);
    }

    // Block until group->sem is released (when worker finishes the Nth task).
    // Bounded wait: 30 seconds. If we exceed, the pool is broken/stuck and
    // we return false rather than hang the caller forever.
    DWORD wait = WaitForSingleObject(group->sem, 30000);
    bool ok = (wait == WAIT_OBJECT_0);
    if (!ok) {
        OD_LOG("[RenderPool] RunParallel: timeout/error waiting for group "
               "sem (wait=%lu, counter=%ld/%u)",
               wait, (long)group->counter, numTasks);
    }

    // Cleanup. By now the worker has finished all tasks AND zeroed each
    // task's [+0x8]/[+0x10] — task storage is safe to free.
    CloseHandle(group->sem);
    DeleteCriticalSection(&group->cs);
    std::free(group);
    std::free(tasks);

    return ok;
}

// =============================================================================
// ParallelFor — divide [start, end) across workers
// =============================================================================

namespace {
struct ParallelForData {
    uint32_t start;
    uint32_t end;
    uint32_t taskCount;
    void   (*body)(uint32_t, void*);
    void*    userCtx;
};

void ParallelForTaskShim(uint32_t taskIdx, void* userData) {
    auto* d = static_cast<ParallelForData*>(userData);
    const uint32_t total = d->end - d->start;
    const uint32_t chunk = (total + d->taskCount - 1) / d->taskCount;
    const uint32_t lo = d->start + taskIdx * chunk;
    uint32_t hi = lo + chunk;
    if (hi > d->end) hi = d->end;
    for (uint32_t i = lo; i < hi; ++i) {
        d->body(i, d->userCtx);
    }
}
}  // namespace

bool ParallelFor(uint32_t start, uint32_t end,
                 void (*body)(uint32_t, void*),
                 void* userData) {
    if (end <= start || !body) return true;
    if (!g_pool.load(std::memory_order_acquire)) return false;
    const uint32_t total = end - start;
    // Cap at 6 (pool worker count). For very small ranges, drop task count
    // to avoid more workers than work.
    uint32_t taskCount = total < 6u ? total : 6u;
    if (taskCount == 0) taskCount = 1;
    ParallelForData d{ start, end, taskCount, body, userData };
    return RunParallel(taskCount, ParallelForTaskShim, &d);
}

bool Install() {
    if (g_installed.load(std::memory_order_acquire)) return true;

    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
        OD_LOG("[RenderPool] MH_Initialize failed: %d", (int)s);
        return false;
    }

    LPVOID target = reinterpret_cast<LPVOID>(static_cast<uintptr_t>(kVA_PoolCtor));
    s = MH_CreateHook(target,
                      reinterpret_cast<LPVOID>(HookedPoolCtor_Naked),
                      reinterpret_cast<LPVOID*>(&g_origPoolCtor));
    if (s != MH_OK) {
        OD_LOG("[RenderPool] MH_CreateHook(sub_A5B050) failed: %d", (int)s);
        return false;
    }
    s = MH_EnableHook(target);
    if (s != MH_OK) {
        OD_LOG("[RenderPool] MH_EnableHook(sub_A5B050) failed: %d", (int)s);
        return false;
    }

    g_installed.store(true, std::memory_order_release);
    g_installTime     = std::chrono::steady_clock::now();
    g_lastLog         = g_installTime;
    g_lastScanAttempt = g_installTime;
    OD_LOG("[RenderPool] Installed. Hook on sub_A5B050 @ 0x%08X (trampoline=%p). "
           "If pool ctor already ran (TLS-callback timing), memory-scan "
           "fallback engages after warmup.",
           (unsigned)kVA_PoolCtor, (void*)g_origPoolCtor);
    return true;
}

void Shutdown() {
    if (!g_installed.load(std::memory_order_acquire)) return;
    LPVOID target = reinterpret_cast<LPVOID>(static_cast<uintptr_t>(kVA_PoolCtor));
    MH_DisableHook(target);
    MH_RemoveHook(target);
    g_installed.store(false, std::memory_order_release);
    g_pool.store(nullptr, std::memory_order_release);
    OD_LOG("[RenderPool] Shutdown.");
}

void* GetPool() {
    return g_pool.load(std::memory_order_acquire);
}

void SetQuietMode(bool quiet) {
    g_quiet.store(quiet, std::memory_order_release);
}

void MaybeLogStats() {
    if (!g_installed.load(std::memory_order_acquire)) return;

    DoObserveTick();
    MaybeVerifyPool();

    // 2026-05-05: Skyrim never releases pool->workerSem (no caller of
    // sub_A5AD60 in the entire IDA xref dump, and no observed task in 76s of
    // gameplay). The pool is dormant — we wake it ourselves. WakePoolIfDormant
    // is idempotent (set-once flag with retry-on-failure logic) and safe to
    // call repeatedly.
    if (g_pool.load(std::memory_order_acquire)) {
        WakePoolIfDormant();
    }

    // Phase 2 self-test: previously gated on g_observeNonEmpty > 0 (i.e., wait
    // until we observe Skyrim queue something). Dropped because Skyrim never
    // queues anything — the gate would never open and the self-test would
    // never run. Now triggers as soon as the pool is captured and at least
    // 1 second has elapsed since install (give the ctor time to finish).
    if (!g_selfTestRan.load(std::memory_order_acquire) &&
        g_pool.load(std::memory_order_acquire)) {
        auto sinceInstall = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - g_installTime).count();
        if (sinceInstall >= 1000) {
            RunSelfTestOnce();
        }
    }

    // Scaling test — runs after the self-test passes. Measures real-world
    // multi-core throughput: how much speedup do we actually get from 6
    // parallel workers vs 1? Output is a single log line with the speedup
    // factor. This is the empirical proof that the multi-core mod's
    // foundation delivers real parallelism, not just deferred scheduling.
    if (g_selfTestRan.load(std::memory_order_acquire) &&
        !g_scalingTestRan.load(std::memory_order_acquire)) {
        RunScalingTestOnce();
    }

    // Memory-scan fallback. Attempt every ~5 seconds until either we capture
    // the pool or we hit kMaxScanAttempts. The pool may not exist immediately
    // at our install time — Skyrim might construct it later in init. Retrying
    // covers that case without us having to predict the timing.
    if (!g_pool.load(std::memory_order_acquire) &&
        g_scanAttempts.load(std::memory_order_acquire) < kMaxScanAttempts) {
        auto now = std::chrono::steady_clock::now();
        auto sinceLastScan = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - g_lastScanAttempt).count();
        // First attempt: 1.5s after install (give Skyrim a moment to construct).
        // Subsequent: every 5s.
        bool shouldScan = false;
        if (g_scanAttempts.load(std::memory_order_acquire) == 0) {
            auto sinceInstall = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - g_installTime).count();
            shouldScan = (sinceInstall >= 1500);
        } else {
            shouldScan = (sinceLastScan >= 5000);
        }
        if (shouldScan) {
            g_lastScanAttempt = now;
            TryMemoryScanFallback();
        }
    }

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog);
    if (elapsed.count() < 5000) return;
    g_lastLog = now;
    if (g_quiet.load(std::memory_order_acquire)) return;

    void* pool = g_pool.load(std::memory_order_acquire);
    const char* via = g_capturedViaHook ? "hook"
                    : g_capturedViaScan ? "scan"
                                        : "(not yet)";
    OD_LOG("[RenderPool] pool=%p via=%s polls=%u nonEmpty=%u peakFilled=%u",
           pool, via,
           g_observePolls.load(std::memory_order_relaxed),
           g_observeNonEmpty.load(std::memory_order_relaxed),
           g_observeTaskMaxSeen.load(std::memory_order_relaxed));

    int active = 0;
    for (size_t i = 0; i < kVtableBuckets; ++i) {
        if (g_vtables[i].vtablePtr) ++active;
    }
    if (active == 0) {
        if (pool) {
            OD_LOG("[RenderPool] No task vtables observed yet. Pool is idle or "
                   "tasks complete faster than the 4 Hz poll. Engage heavier scenes.");
        }
        return;
    }
    OD_LOG("[RenderPool] %d unique task vtables observed (slot[0]=dtor, "
           "slot[1]=Validate, slot[2]=Run, slot[3]=Finish per sub_A5AE90 disasm):",
           active);
    for (size_t i = 0; i < kVtableBuckets; ++i) {
        if (!g_vtables[i].vtablePtr) continue;
        OD_LOG("[RenderPool]   vt=0x%08X hits=%ld dtor=0x%08X Validate=0x%08X Run=0x%08X Finish=0x%08X",
               (unsigned)g_vtables[i].vtablePtr,
               (long)g_vtables[i].hits,
               (unsigned)g_vtables[i].slot0,
               (unsigned)g_vtables[i].slot1,
               (unsigned)g_vtables[i].slot2,
               (unsigned)g_vtables[i].slot3);
    }
}

}
