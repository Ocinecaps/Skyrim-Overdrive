#include "NiDX9Hooks.h"
#include "DebugLogger.h"
#include "D3D9Replay.h"
#include "D3D9PipelineDispatcher.h"
#include "MinHook/MinHook.h"

#include <windows.h>
#include <chrono>
#include <d3d9.h>

namespace overdrive::nidx9 {

// One counter and one trampoline pointer per function. They MUST be globals
// (not statics inside a function) because the naked-asm thunks reference them
// by name and the assembler resolves to absolute addresses at link time.
volatile uint32_t g_count_CB7E80 = 0;
volatile uint32_t g_count_B06250 = 0;
volatile uint32_t g_count_CA2610 = 0;

// Captured by each thunk on every entry — the thread ID currently executing
// the hot sub. Lets the scenegraph profiler aim its EIP sampler at the right
// thread (which is NOT the one that calls Present, on Skyrim — see header).
volatile uint32_t g_lastTid_CB7E80 = 0;
volatile uint32_t g_lastTid_B06250 = 0;
volatile uint32_t g_lastTid_CA2610 = 0;

// Week 2 record-and-replay stats. Incremented on each hot-sub outer entry/exit.
volatile uint32_t g_recOuterEntries  = 0;
volatile uint32_t g_recOuterExits    = 0;
volatile uint32_t g_recReplaysIssued = 0;
volatile uint32_t g_recRecordsTotal  = 0;

// =============================================================================
// Week 3a: outer-entry retaddr histogram
// =============================================================================
//
// Per the scenegraph internals notes (memory: reference_skyrim_scenegraph_internals)
// the hot subs are vtable[25/26] of NiObject-derived classes — they're only
// invoked via `call dword ptr [reg+0x64]` / `[reg+0x68]`, which means IDA's
// xref scanner can't find their parent call site without runtime capture.
//
// Our wrapping thunk has the perfect capture point: EnterThunk_HotSub runs at
// depth=0 only on the OUTER entry (the parent's call into the scenegraph).
// Bucketing those retaddrs surfaces the parent loop's call site(s).
//
// Lock-free: linear scan + InterlockedCompareExchange to claim empty slots.
// Buckets are tiny (64 slots) — in practice we expect <10 unique retaddrs
// since the scenegraph is driven from a small number of top-level call sites.

constexpr size_t kOuterRetBuckets = 64;
struct OuterRetEntry {
    volatile LONG retaddr;  // 0 = empty
    volatile LONG hits;
};
OuterRetEntry g_outerRetBuckets[kOuterRetBuckets] = {};
volatile LONG g_outerRetDropped = 0;

static void NoteOuterRetaddr(DWORD retaddr) {
    const LONG ra = (LONG)retaddr;
    for (size_t i = 0; i < kOuterRetBuckets; ++i) {
        const LONG existing = g_outerRetBuckets[i].retaddr;
        if (existing == ra) {
            InterlockedIncrement(&g_outerRetBuckets[i].hits);
            return;
        }
        if (existing == 0) {
            const LONG prev = InterlockedCompareExchange(&g_outerRetBuckets[i].retaddr, ra, 0);
            if (prev == 0 || prev == ra) {
                InterlockedIncrement(&g_outerRetBuckets[i].hits);
                return;
            }
        }
    }
    InterlockedIncrement(&g_outerRetDropped);
}

namespace {

// MinHook fills these in via the ppOriginal out-param of MH_CreateHook.
// Until MinHook fills them, jumping through them would crash, so we keep
// hooks DISABLED until trampolines are populated.
void* g_tramp_CB7E80 = nullptr;
void* g_tramp_B06250 = nullptr;
void* g_tramp_CA2610 = nullptr;

// =============================================================================
// Week 2 record-and-replay wrapper machinery
// =============================================================================
//
// Each hot-sub thunk wraps the original sub like this:
//   1. Save caller's retaddr to a per-thread shadow stack
//   2. Replace caller's retaddr (on stack) with `Thunk_Resume`
//   3. On outer entry (depth was 0), call StartRecording so D3D9 calls inside
//      the sub buffer instead of executing
//   4. jmp to MinHook trampoline. Original sub runs, all D3D9 calls inside it
//      go into g_buffer. Original returns to `Thunk_Resume` (because we
//      replaced retaddr).
//   5. Thunk_Resume: on outer exit (depth becoming 0), StopRecording and
//      Replay the buffer through the real D3D9 device.
//   6. Pop saved retaddr from shadow stack and `ret` to the original caller.
//
// Calling-convention preservation: the resume sequence
//      sub  esp, 4
//      mov  [esp], <retaddr>
//      ret
// works for both cdecl and stdcall:
//   - stdcall: orig's `ret N` cleaned its args, ESP is past args. Push retaddr
//     just below current ESP and bounce off — caller of thunk doesn't clean
//     args (stdcall convention says callee did). ✓
//   - cdecl: orig's `ret` left ESP at first arg. Push retaddr just below
//     (overwriting nothing — there's room in the red zone). Caller of thunk
//     does `add esp, N` after our ret. ✓
// In all cases ECX/EAX/EDX are caller-saved so we can use them as scratch in
// the resume sequence.
//
// Recursion safety: depth counter + shadow ret stack are __declspec(thread).
// If sub_CB7E80 recursively calls sub_B06250 (or itself), inner entries just
// bump depth; only the outer entry/exit pair toggles recording state. Buffer
// is shared across nested entries on the same thread.
//
// Out-of-thread safety: each thread has its own t_recordDepth, t_savedRet,
// and (via the existing replay layer) its own g_buffer. No cross-thread state.

constexpr int kShadowMax = 64;
__declspec(thread) DWORD t_recordDepth = 0;
__declspec(thread) DWORD t_savedRet[kShadowMax] = {};

}  // namespace

// Worker threads (in RenderWorkerPool.cpp) set this to true during job
// execution. ExitThunk_HotSub at depth=0 reads it: if true, leave the
// recorded buffer alone so the pool's coordinator can drain it later;
// if false (default — render thread), replay locally.
__declspec(thread) bool t_skipReplay = false;

namespace {

// Forward decl — defined in asm at the bottom of this file.
extern "C" void Thunk_Resume();

// CRITICAL: when the pipeline dispatcher is active, hot-sub recording MUST
// be disabled. Otherwise the timeline corrupts:
//
//   T_record: Mirror_BeginScene → pipeline-enqueued (queued, not dispatched)
//   T_record: Mirror_SetTransform → pipeline-enqueued
//   T_record: enters sub_CB7E80 → would StartRecording locally
//             Mirror_DrawIndexedPrimitive → would record to thread_local g_buffer
//             ExitThunk_HotSub at depth=0 → would Replay() inline:
//                  orig<DrawIndexedPrimitive>() on T_record → real D3D9 sees Draw,
//                  but pipeline hasn't dispatched BeginScene/SetTransform yet.
//                  → wrong-state draw, visual glitches.
//
// Disabling hot-sub recording when pipeline is active routes ALL Mirror_*
// calls (including those inside hot subs) through the pipeline. Global order
// is preserved: BeginScene, ..., SetTexture, Draw, ..., EndScene — exactly
// as Skyrim issues them. The dispatcher replays in that order.
//
// The depth counter, retaddr histogram, and outer-entry tracking remain
// active (for instrumentation and the [NiDX9-PARENT] log line); they don't
// require the recording state.

extern "C" void __cdecl EnterThunk_HotSub(DWORD retaddr) {
    if (t_recordDepth < kShadowMax) {
        t_savedRet[t_recordDepth] = retaddr;
    }
    if (t_recordDepth == 0) {
        // OUTER entry — this retaddr is the parent loop's call site. Bucket it.
        NoteOuterRetaddr(retaddr);
        if (!overdrive::pipeline::IsActive()) {
            // Pipeline OFF: use the legacy hot-sub recording optimization.
            overdrive::replay::StartRecording();
        }
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_recOuterEntries));
    }
    ++t_recordDepth;
}

// Pops the saved retaddr from the shadow stack and returns it. On outer exit
// (depth becoming 0), StopRecording + Replay through the captured device —
// UNLESS t_skipReplay is set (worker threads, RenderWorkerPool only) OR the
// pipeline dispatcher is active (in which case Mirror_* already enqueued
// directly to the pipeline buffer — there's nothing to replay locally).
extern "C" DWORD __cdecl ExitThunk_HotSub() {
    if (t_recordDepth > 0) --t_recordDepth;

    DWORD retaddr = (t_recordDepth < kShadowMax) ? t_savedRet[t_recordDepth] : 0;

    if (t_recordDepth == 0) {
        if (!overdrive::pipeline::IsActive()) {
            overdrive::replay::StopRecording();
            if (!t_skipReplay) {
                const auto& buf = overdrive::replay::CurrentBuffer();
                if (!buf.records.empty()) {
                    IDirect3DDevice9* dev = overdrive::replay::GetDevice();
                    if (dev) {
                        overdrive::replay::Replay(dev, buf);
                        overdrive::replay::NoteReplayedCount(
                            static_cast<uint32_t>(buf.records.size()));
                        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_recReplaysIssued));
                        InterlockedExchangeAdd(reinterpret_cast<volatile LONG*>(&g_recRecordsTotal),
                                               static_cast<LONG>(buf.records.size()));
                    }
                    overdrive::replay::CurrentBuffer().Clear();
                }
            }
        }
        InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_recOuterExits));
    }

    return retaddr;
}

// =============================================================================
// Naked thunks — entry stubs and shared resume label.
// =============================================================================
//
// Each entry thunk:
//   - Saves EAX/ECX/EDX (potentially clobbered by EnterThunk_HotSub which is
//     a normal C function and may trash all three per Windows x86 ABI).
//   - Reads caller's retaddr from [esp+12] (12 = 3 saved regs * 4).
//   - Calls EnterThunk_HotSub(retaddr) — saves retaddr to shadow stack and
//     starts recording on outer entry.
//   - Replaces caller's retaddr with the address of Thunk_Resume so the
//     original sub will return to our epilogue.
//   - Restores EAX/ECX/EDX (ECX preservation matters for thiscall — the
//     hot subs are vtable methods on NiObject, ECX = `this`).
//   - Increments the existing per-sub counter and stamps g_lastTid_*.
//   - Tail-jumps to the MinHook trampoline.

extern "C" __declspec(naked) void Thunk_CB7E80() {
    __asm {
        push eax
        push ecx
        push edx
        mov  eax, [esp+12]              ; eax = caller's retaddr
        push eax
        call EnterThunk_HotSub
        add  esp, 4
        mov  eax, offset Thunk_Resume
        mov  [esp+12], eax              ; replace caller's retaddr -> Thunk_Resume
        pop  edx
        pop  ecx
        pop  eax
        ; Existing instrumentation: counter + last-tid.
        push eax
        mov  eax, fs:[0x24]
        mov  [g_lastTid_CB7E80], eax
        lock inc dword ptr [g_count_CB7E80]
        pop  eax
        jmp  dword ptr [g_tramp_CB7E80]
    }
}

extern "C" __declspec(naked) void Thunk_B06250() {
    __asm {
        push eax
        push ecx
        push edx
        mov  eax, [esp+12]
        push eax
        call EnterThunk_HotSub
        add  esp, 4
        mov  eax, offset Thunk_Resume
        mov  [esp+12], eax
        pop  edx
        pop  ecx
        pop  eax
        push eax
        mov  eax, fs:[0x24]
        mov  [g_lastTid_B06250], eax
        lock inc dword ptr [g_count_B06250]
        pop  eax
        jmp  dword ptr [g_tramp_B06250]
    }
}

extern "C" __declspec(naked) void Thunk_CA2610() {
    __asm {
        push eax
        push ecx
        push edx
        mov  eax, [esp+12]
        push eax
        call EnterThunk_HotSub
        add  esp, 4
        mov  eax, offset Thunk_Resume
        mov  [esp+12], eax
        pop  edx
        pop  ecx
        pop  eax
        push eax
        mov  eax, fs:[0x24]
        mov  [g_lastTid_CA2610], eax
        lock inc dword ptr [g_count_CA2610]
        pop  eax
        jmp  dword ptr [g_tramp_CA2610]
    }
}

// Shared resume label. Reached when the original hot sub does its `ret` —
// retaddr was replaced with this address. EAX/EDX hold the original's return
// value; ESP is wherever the original's calling convention left it.
extern "C" __declspec(naked) void Thunk_Resume() {
    __asm {
        ; Preserve the original's return value (EAX, EDX) and flags so we can
        ; freely call C from here.
        pushfd
        push eax
        push ecx
        push edx

        call ExitThunk_HotSub           ; returns retaddr in EAX

        ; Move retaddr to ECX (caller-saved scratch). After we restore the
        ; spilled regs, ECX still holds it.
        mov  ecx, eax

        ; Restore EDX (return-value high half), then SKIP the spilled ECX
        ; slot — we deliberately overwrote ECX above; the original's caller
        ; doesn't depend on ECX preservation in any of: cdecl, stdcall,
        ; or thiscall (where ECX = `this` is callee-clobberable).
        pop  edx
        add  esp, 4                     ; discard spilled ECX
        pop  eax                        ; restore EAX (return-value low half)
        popfd

        ; ESP is now exactly where the original sub left it. Drop a fresh
        ; retaddr (the caller's actual return target) just below and bounce.
        sub  esp, 4
        mov  [esp], ecx
        ret
    }
}

struct HookSpec {
    const char* name;
    LPVOID      target;
    LPVOID      detour;
    void**      trampolineSlot;
};

HookSpec g_hooks[] = {
    { "sub_CB7E80", reinterpret_cast<LPVOID>(0x00CB7E80), reinterpret_cast<LPVOID>(Thunk_CB7E80), &g_tramp_CB7E80 },
    { "sub_B06250", reinterpret_cast<LPVOID>(0x00B06250), reinterpret_cast<LPVOID>(Thunk_B06250), &g_tramp_B06250 },
    { "sub_CA2610", reinterpret_cast<LPVOID>(0x00CA2610), reinterpret_cast<LPVOID>(Thunk_CA2610), &g_tramp_CA2610 },
};

std::chrono::steady_clock::time_point g_lastLog;
uint32_t g_lastSnap[3] = { 0, 0, 0 };
uint32_t g_lastSnapRec[4] = { 0, 0, 0, 0 };

}  // namespace

bool Install() {
    // MinHook may already be initialized by D3D9Hook. Both error codes are OK.
    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
        OD_LOG("[NiDX9] MH_Initialize failed: %s", MH_StatusToString(s));
        return false;
    }

    bool anyHooked = false;
    for (auto& h : g_hooks) {
        s = MH_CreateHook(h.target, h.detour, h.trampolineSlot);
        if (s != MH_OK) {
            OD_LOG("[NiDX9] CreateHook(%s @ %p) failed: %s",
                   h.name, h.target, MH_StatusToString(s));
            continue;
        }
        s = MH_EnableHook(h.target);
        if (s != MH_OK) {
            OD_LOG("[NiDX9] EnableHook(%s) failed: %s", h.name, MH_StatusToString(s));
            MH_RemoveHook(h.target);
            continue;
        }
        OD_LOG("[NiDX9] Hooked %s @ %p (trampoline=%p, thunk=%p)",
               h.name, h.target, *h.trampolineSlot, h.detour);
        anyHooked = true;
    }

    g_lastLog = std::chrono::steady_clock::now();
    if (anyHooked) {
        OD_LOG("[NiDX9] Install complete. Stats logged every 5s as `[NiDX9] last Ns: ...`");
        OD_LOG("[NiDX9] Week 2 record-and-replay ARMED: each hot-sub call now records "
               "D3D9 ops into a per-thread buffer, then Replay()s after the sub returns.");

        // Week 3a follow-up: dump the bytes around the parent-loop call sites
        // identified by the [NiDX9-PARENT] histogram. Site #1 ret=0x00CB1BF6
        // (91.69%), site #2 ret=0x00CAD9D3 (8.31%). Lets us see the exact
        // call instruction (FF 50 64 vs FF 50 68) and what register holds the
        // receiver — needed to design the loop-level hook.
        struct Site { const char* name; uintptr_t retaddr; };
        const Site sites[] = {
            { "site#1 (parent loop, 91.69%)", 0x00CB1BF6 },
            { "site#2 (sub_B06250 direct,  8.31%)", 0x00CAD9D3 },
        };
        for (const auto& s : sites) {
            // Read 16 bytes ending at retaddr (so we cover the call instruction
            // and the next ~8 bytes for context). Guard with IsBadReadPtr —
            // unlikely to fail since these are inside TESV.exe's .text.
            uint8_t bytes[16] = {};
            const uint8_t* base = reinterpret_cast<const uint8_t*>(s.retaddr) - 8;
            if (!IsBadReadPtr(base, sizeof(bytes))) {
                memcpy(bytes, base, sizeof(bytes));
                OD_LOG("[NiDX9-BYTES] %s ret=0x%08lX  bytes[ret-8..ret+7]: "
                       "%02X %02X %02X %02X %02X %02X %02X %02X | "
                       "%02X %02X %02X %02X %02X %02X %02X %02X",
                       s.name, (unsigned long)s.retaddr,
                       bytes[0], bytes[1], bytes[2], bytes[3],
                       bytes[4], bytes[5], bytes[6], bytes[7],
                       bytes[8], bytes[9], bytes[10], bytes[11],
                       bytes[12], bytes[13], bytes[14], bytes[15]);
                OD_LOG("[NiDX9-BYTES]   layout: bytes[0..7] = pre-call (8 bytes "
                       "before retaddr); bytes[5..7] would be FF 50 NN if vtable "
                       "call; bytes[3..7] would be E8 NN NN NN NN if direct call");
            } else {
                OD_LOG("[NiDX9-BYTES] %s ret=0x%08lX  bytes UNREADABLE",
                       s.name, (unsigned long)s.retaddr);
            }
        }
    } else {
        OD_LOG("[NiDX9] Install: NO functions hooked. Either addresses are stale "
               "or MinHook can't decode the prologues.");
    }
    return anyHooked;
}

void MaybeLogStats() {
    const auto now     = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog);
    if (elapsed.count() < 5000) return;
    g_lastLog = now;

    const uint32_t c0 = g_count_CB7E80;
    const uint32_t c1 = g_count_B06250;
    const uint32_t c2 = g_count_CA2610;
    const uint32_t d0 = c0 - g_lastSnap[0];
    const uint32_t d1 = c1 - g_lastSnap[1];
    const uint32_t d2 = c2 - g_lastSnap[2];
    g_lastSnap[0] = c0;
    g_lastSnap[1] = c1;
    g_lastSnap[2] = c2;

    const uint32_t r0 = g_recOuterEntries;
    const uint32_t r1 = g_recOuterExits;
    const uint32_t r2 = g_recReplaysIssued;
    const uint32_t r3 = g_recRecordsTotal;
    const uint32_t dr0 = r0 - g_lastSnapRec[0];
    const uint32_t dr1 = r1 - g_lastSnapRec[1];
    const uint32_t dr2 = r2 - g_lastSnapRec[2];
    const uint32_t dr3 = r3 - g_lastSnapRec[3];
    g_lastSnapRec[0] = r0;
    g_lastSnapRec[1] = r1;
    g_lastSnapRec[2] = r2;
    g_lastSnapRec[3] = r3;

    const double secs = elapsed.count() / 1000.0;
    OD_LOG("[NiDX9] last %.1fs: "
           "CB7E80 total=%u (+%.0f/s) tid=%u, "
           "B06250 total=%u (+%.0f/s) tid=%u, "
           "CA2610 total=%u (+%.0f/s) tid=%u",
           secs,
           c0, (double)d0 / secs, (unsigned)g_lastTid_CB7E80,
           c1, (double)d1 / secs, (unsigned)g_lastTid_B06250,
           c2, (double)d2 / secs, (unsigned)g_lastTid_CA2610);
    OD_LOG("[NiDX9-RR] last %.1fs: outerEntries=%u (+%u) outerExits=%u (+%u) "
           "replays=%u (+%u) recordsTotal=%u (+%u, avg=%.1f rec/replay)",
           secs,
           r0, dr0, r1, dr1, r2, dr2, r3, dr3,
           dr2 ? (double)dr3 / dr2 : 0.0);

    // Outer-retaddr histogram dump — surfaces the parent-loop call sites for
    // Week 3 parallelization. Throttled to once per 30s (the bucket counts are
    // cumulative; logging this every 5s would just be noise after warmup).
    static int sLogTickCounter = 0;
    if (++sLogTickCounter >= 6) {
        sLogTickCounter = 0;

        struct Snapshot { LONG retaddr; LONG hits; };
        Snapshot snap[kOuterRetBuckets];
        size_t snapCount = 0;
        LONG totalHits = 0;
        for (size_t i = 0; i < kOuterRetBuckets; ++i) {
            const LONG ra = g_outerRetBuckets[i].retaddr;
            const LONG hits = g_outerRetBuckets[i].hits;
            if (ra != 0 && hits > 0) {
                snap[snapCount++] = { ra, hits };
                totalHits += hits;
            }
        }
        // Insertion sort by hits desc — table is small, no need for qsort.
        for (size_t i = 1; i < snapCount; ++i) {
            Snapshot v = snap[i];
            size_t j = i;
            while (j > 0 && snap[j - 1].hits < v.hits) {
                snap[j] = snap[j - 1];
                --j;
            }
            snap[j] = v;
        }

        OD_LOG("[NiDX9-PARENT] outer-entry retaddr histogram: %zu unique sites, "
               "%ld total hits, %ld dropped (bucket overflow). Top 15:",
               snapCount, (long)totalHits, (long)g_outerRetDropped);
        const size_t shown = snapCount < 15 ? snapCount : 15;
        for (size_t i = 0; i < shown; ++i) {
            const double pct = totalHits ? (100.0 * snap[i].hits / totalHits) : 0.0;
            // call_site_FF50_64 = retaddr - 3 (FF 50 64 = call [reg+0x64], 3 bytes)
            // call_site_FF50_68 = retaddr - 3 (FF 50 68 = call [reg+0x68])
            // call_site_E8     = retaddr - 5 (E8 imm32 = direct relative call)
            // Pick whichever pattern matches the bytes at that address in IDA.
            OD_LOG("[NiDX9-PARENT]   #%-2zu  ret=0x%08lX  cs_FF50=0x%08lX  cs_E8=0x%08lX  "
                   "hits=%-8ld  %5.2f%%",
                   i + 1, (unsigned long)snap[i].retaddr,
                   (unsigned long)(snap[i].retaddr - 3),
                   (unsigned long)(snap[i].retaddr - 5),
                   (long)snap[i].hits, pct);
        }
    }
}

}  // namespace
