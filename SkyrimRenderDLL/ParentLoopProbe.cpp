#include "ParentLoopProbe.h"
#include "DebugLogger.h"
#include "MinHook/MinHook.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>

namespace overdrive::parentloop {

// =============================================================================
// What we're after
// =============================================================================
//
// From slim DLL D3DX caller histogram (110s session):
//   - 50% of D3DXMatrixMultiplyTranspose calls return to 0x00CB7EE0 (inside
//     sub_CB7E80) — sub_CB7E80 is the dominant matrix-work function
//   - 25% return to 0x00CA26EE (inside sub_CA2610) — second hot
//   - sub_CB1480 / sub_CB1FF0 hooked previously: TOTAL=1 each → not the
//     per-frame loop dispatcher we thought they were
//
// So: hook sub_CB7E80 and sub_CA2610 directly. The dominant caller retaddr
// of EACH is the per-frame loop iterating over scenegraph nodes. THAT is
// the Phase 3 ParallelFor target.
//
// We also keep the sub_CB1480/sub_CB1FF0 hooks for completeness; they
// produced ~0 traffic last session, confirming they're not on the hot path.

namespace {

// =============================================================================
// Histogram primitive (lock-free, 64 buckets per target)
// =============================================================================

constexpr size_t kBuckets = 64;

struct Entry { volatile LONG ra; volatile LONG hits; };

inline void NoteCaller(Entry* buckets, volatile LONG* total,
                       volatile LONG* dropped, DWORD ra) {
    InterlockedIncrement(total);
    const LONG r = (LONG)ra;
    for (size_t i = 0; i < kBuckets; ++i) {
        const LONG existing = buckets[i].ra;
        if (existing == r) {
            InterlockedIncrement(&buckets[i].hits);
            return;
        }
        if (existing == 0) {
            const LONG prev = InterlockedCompareExchange(&buckets[i].ra, r, 0);
            if (prev == 0 || prev == r) {
                InterlockedIncrement(&buckets[i].hits);
                return;
            }
        }
    }
    InterlockedIncrement(dropped);
}

// =============================================================================
// Per-target state — one block per hooked function
// =============================================================================

struct Target {
    uintptr_t   va;
    const char* name;
    void**      trampolineSlot;  // points at the named global below
    Entry       buckets[kBuckets];
    LONG        total;
    LONG        dropped;
};

// Indices match the detour and trampoline naming below.
enum TargetIdx : int {
    T_CB1FF0 = 0,   // scalar dtor wrapper (rare)
    T_CB1480 = 1,   // dtor body            (rare)
    T_CB7E80 = 2,   // HOT — 50% of MMT comes from inside this
    T_CA2610 = 3,   // HOT — second hottest
    T_COUNT
};

}  // namespace

// Trampolines kept as named globals (not indexed via asm into the Target
// array — sizeof(Target) is ~532 bytes, indexing math in naked asm is too
// error-prone). MH_CreateHook fills these directly.
extern "C" {
    void* g_tramp_CB1FF0 = nullptr;
    void* g_tramp_CB1480 = nullptr;
    void* g_tramp_CB7E80 = nullptr;
    void* g_tramp_CA2610 = nullptr;
}

namespace {

Target g_targets[T_COUNT] = {
    { 0x00CB1FF0, "sub_CB1FF0 (scalar dtor wrapper)",        &g_tramp_CB1FF0, {}, 0, 0 },
    { 0x00CB1480, "sub_CB1480 (dtor body)",                  &g_tramp_CB1480, {}, 0, 0 },
    { 0x00CB7E80, "sub_CB7E80 (HOT render-prep, 50% of MMT)",&g_tramp_CB7E80, {}, 0, 0 },
    { 0x00CA2610, "sub_CA2610 (HOT render-prep, 25% of MMT)",&g_tramp_CA2610, {}, 0, 0 },
};

}  // namespace

// =============================================================================
// __cdecl shims (one per target — naked detours call into these)
// =============================================================================

extern "C" {

void __cdecl OnCall_CB1FF0(DWORD ra) {
    auto& t = g_targets[T_CB1FF0];
    NoteCaller(t.buckets, &t.total, &t.dropped, ra);
}
void __cdecl OnCall_CB1480(DWORD ra) {
    auto& t = g_targets[T_CB1480];
    NoteCaller(t.buckets, &t.total, &t.dropped, ra);
}
void __cdecl OnCall_CB7E80(DWORD ra) {
    auto& t = g_targets[T_CB7E80];
    NoteCaller(t.buckets, &t.total, &t.dropped, ra);
}
void __cdecl OnCall_CA2610(DWORD ra) {
    auto& t = g_targets[T_CA2610];
    NoteCaller(t.buckets, &t.total, &t.dropped, ra);
}

}  // extern "C"

// =============================================================================
// Naked detours — capture the caller's retaddr (at [esp+0] on entry), then
// JMP to the trampoline. ESP balanced end-to-end, ECX preserved.
// =============================================================================

// Each detour is mechanically identical except it calls a different shim and
// jumps through a different trampoline. Macros would obscure the asm; just
// duplicate.

extern "C" __declspec(naked) void Detour_CB1FF0() {
    __asm {
        push    eax
        push    ecx
        mov     eax, [esp+8]
        push    eax
        call    OnCall_CB1FF0
        add     esp, 4
        pop     ecx
        pop     eax
        jmp     dword ptr [g_tramp_CB1FF0]
    }
}

extern "C" __declspec(naked) void Detour_CB1480() {
    __asm {
        push    eax
        push    ecx
        mov     eax, [esp+8]
        push    eax
        call    OnCall_CB1480
        add     esp, 4
        pop     ecx
        pop     eax
        jmp     dword ptr [g_tramp_CB1480]
    }
}

extern "C" __declspec(naked) void Detour_CB7E80() {
    __asm {
        push    eax
        push    ecx
        mov     eax, [esp+8]
        push    eax
        call    OnCall_CB7E80
        add     esp, 4
        pop     ecx
        pop     eax
        jmp     dword ptr [g_tramp_CB7E80]
    }
}

extern "C" __declspec(naked) void Detour_CA2610() {
    __asm {
        push    eax
        push    ecx
        mov     eax, [esp+8]
        push    eax
        call    OnCall_CA2610
        add     esp, 4
        pop     ecx
        pop     eax
        jmp     dword ptr [g_tramp_CA2610]
    }
}

// =============================================================================
// Public API
// =============================================================================

namespace {

std::atomic<bool> g_installed{false};
std::chrono::steady_clock::time_point g_lastLog;

bool InstallOne(int idx, void* detour) {
    auto& t = g_targets[idx];
    LPVOID target = reinterpret_cast<LPVOID>(t.va);
    MH_STATUS s = MH_CreateHook(target, detour, t.trampolineSlot);
    if (s != MH_OK) {
        OD_LOG("[ParentProbe] CreateHook(%s @ 0x%08X) failed: %d",
               t.name, (unsigned)t.va, (int)s);
        return false;
    }
    s = MH_EnableHook(target);
    if (s != MH_OK) {
        OD_LOG("[ParentProbe] EnableHook(%s @ 0x%08X) failed: %d",
               t.name, (unsigned)t.va, (int)s);
        return false;
    }
    return true;
}

}  // namespace

bool Install() {
    if (g_installed.load(std::memory_order_acquire)) return true;

    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
        OD_LOG("[ParentProbe] MH_Initialize failed: %d", (int)s);
        return false;
    }

    bool ok = true;
    ok &= InstallOne(T_CB1FF0, reinterpret_cast<void*>(&Detour_CB1FF0));
    ok &= InstallOne(T_CB1480, reinterpret_cast<void*>(&Detour_CB1480));
    ok &= InstallOne(T_CB7E80, reinterpret_cast<void*>(&Detour_CB7E80));
    ok &= InstallOne(T_CA2610, reinterpret_cast<void*>(&Detour_CA2610));

    if (!ok) {
        OD_LOG("[ParentProbe] One or more hooks failed to install");
        return false;
    }

    g_installed.store(true, std::memory_order_release);
    g_lastLog = std::chrono::steady_clock::now();
    OD_LOG("[ParentProbe] Installed. 4 hooks: sub_CB1FF0, sub_CB1480, "
           "sub_CB7E80 (HOT), sub_CA2610 (HOT). Per-target retaddr "
           "histograms log every 10s. Dominant retaddr of sub_CB7E80 IS "
           "the per-frame loop driving render-prep — Phase 3 target.");
    return true;
}

void Shutdown() {
    if (!g_installed.load(std::memory_order_acquire)) return;
    for (int i = 0; i < T_COUNT; ++i) {
        LPVOID target = reinterpret_cast<LPVOID>(g_targets[i].va);
        MH_DisableHook(target);
        MH_RemoveHook(target);
    }
    g_installed.store(false, std::memory_order_release);
}

namespace {

void DumpHistogram(const Target& t) {
    if (t.total == 0) {
        OD_LOG("[ParentProbe] %s: total=0 (not yet called this session)", t.name);
        return;
    }
    struct Top { LONG ra; LONG hits; };
    Top top[5] = {};
    int unique = 0;
    for (size_t i = 0; i < kBuckets; ++i) {
        const LONG ra = t.buckets[i].ra;
        const LONG h  = t.buckets[i].hits;
        if (ra == 0) continue;
        ++unique;
        for (int k = 0; k < 5; ++k) {
            if (h > top[k].hits) {
                for (int j = 4; j > k; --j) top[j] = top[j-1];
                top[k] = { ra, h };
                break;
            }
        }
    }
    OD_LOG("[ParentProbe] %s: total=%ld unique=%d dropped=%ld",
           t.name, (long)t.total, unique, (long)t.dropped);
    for (int k = 0; k < 5; ++k) {
        if (top[k].hits == 0) break;
        double pct = 100.0 * (double)top[k].hits / (double)t.total;
        OD_LOG("[ParentProbe]   #%d  ret=0x%08X  cs_FF15=0x%08X  cs_E8=0x%08X  hits=%ld  %.2f%%",
               k + 1,
               (unsigned)top[k].ra,
               (unsigned)(top[k].ra - 6),
               (unsigned)(top[k].ra - 5),
               top[k].hits, pct);
    }
}

}  // namespace

void MaybeLogStats() {
    if (!g_installed.load(std::memory_order_acquire)) return;
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog).count() < 10000) {
        return;
    }
    g_lastLog = now;
    for (int i = 0; i < T_COUNT; ++i) {
        DumpHistogram(g_targets[i]);
    }
}

}
