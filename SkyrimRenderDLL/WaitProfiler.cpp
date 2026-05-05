#include "WaitProfiler.h"
#include "DebugLogger.h"
#include "MinHook/MinHook.h"

#include <windows.h>
#include <psapi.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>

namespace overdrive::waitprof {

namespace {

// Per-API hash table of caller addresses. Each API has its own table so we
// can break out the breakdown ("WaitForSingleObject was called from X 800
// times" vs WaitForMultipleObjects from Y).
constexpr int kHashSlots = 2048;
struct WaitBucket {
    uint32_t callerVa;     // 0 = empty. Return address from caller.
    uint64_t hits;
    DWORD    lastDwMs;     // last dwMilliseconds (0xFFFFFFFF = INFINITE)
    uint64_t infiniteHits; // count where dwMilliseconds was INFINITE
};

// One table per API.
WaitBucket g_bucketsWFSO[kHashSlots]   = {};   // WaitForSingleObject
WaitBucket g_bucketsWFSOEx[kHashSlots] = {};   // WaitForSingleObjectEx
WaitBucket g_bucketsWFMO[kHashSlots]   = {};   // WaitForMultipleObjects

std::atomic<uint64_t> g_totalCalls_WFSO{0},   g_tesvCalls_WFSO{0};
std::atomic<uint64_t> g_totalCalls_WFSOEx{0}, g_tesvCalls_WFSOEx{0};
std::atomic<uint64_t> g_totalCalls_WFMO{0},   g_tesvCalls_WFMO{0};

uint32_t g_tesvBase = 0, g_tesvEnd = 0;

void* g_origWFSO   = nullptr;
void* g_origWFSOEx = nullptr;
void* g_origWFMO   = nullptr;

std::chrono::steady_clock::time_point g_lastLog;

inline uint32_t MixAddr(uint32_t p) {
    p ^= p >> 16; p *= 0x7feb352d;
    p ^= p >> 15; p *= 0x846ca68b;
    p ^= p >> 16; return p;
}

inline void RecordIntoTable(WaitBucket* table, uint32_t retAddr, DWORD dwMs) {
    uint32_t slot = MixAddr(retAddr) & (kHashSlots - 1);
    for (int probe = 0; probe < 32; ++probe) {
        if (table[slot].callerVa == 0) {
            table[slot].callerVa = retAddr;
            table[slot].hits = 1;
            table[slot].lastDwMs = dwMs;
            if (dwMs == INFINITE) table[slot].infiniteHits = 1;
            return;
        }
        if (table[slot].callerVa == retAddr) {
            ++table[slot].hits;
            table[slot].lastDwMs = dwMs;
            if (dwMs == INFINITE) ++table[slot].infiniteHits;
            return;
        }
        slot = (slot + 1) & (kHashSlots - 1);
    }
}

extern "C" void __cdecl Recorder_WFSO(uint32_t retAddr, DWORD dwMs) {
    g_totalCalls_WFSO.fetch_add(1, std::memory_order_relaxed);
    if (retAddr < g_tesvBase || retAddr >= g_tesvEnd) return;
    g_tesvCalls_WFSO.fetch_add(1, std::memory_order_relaxed);
    RecordIntoTable(g_bucketsWFSO, retAddr, dwMs);
}

extern "C" void __cdecl Recorder_WFSOEx(uint32_t retAddr, DWORD dwMs) {
    g_totalCalls_WFSOEx.fetch_add(1, std::memory_order_relaxed);
    if (retAddr < g_tesvBase || retAddr >= g_tesvEnd) return;
    g_tesvCalls_WFSOEx.fetch_add(1, std::memory_order_relaxed);
    RecordIntoTable(g_bucketsWFSOEx, retAddr, dwMs);
}

extern "C" void __cdecl Recorder_WFMO(uint32_t retAddr, DWORD dwMs) {
    g_totalCalls_WFMO.fetch_add(1, std::memory_order_relaxed);
    if (retAddr < g_tesvBase || retAddr >= g_tesvEnd) return;
    g_tesvCalls_WFMO.fetch_add(1, std::memory_order_relaxed);
    RecordIntoTable(g_bucketsWFMO, retAddr, dwMs);
}

// ===== Naked thunks =====
//
// All three are __stdcall. The thunk preserves volatile regs, captures the
// caller's return address (on top of stack at entry) and the relevant arg,
// invokes the cdecl recorder, restores, then jmp-tail-calls the original.
// Original API does its own ret N which cleans the args and returns to the
// real caller in TESV.exe.
//
// Stack at thunk entry:
//   [esp]    = caller's return address (TESV.exe instruction after the call)
//   [esp+4]  = arg1
//   [esp+8]  = arg2  (if 2-arg API)
//   ...
//
// After our 3 saves (eax, ecx, edx), shift everything by 12.

// WaitForSingleObject(HANDLE hHandle, DWORD dwMs) — dwMs is at [esp+8] orig
extern "C" __declspec(naked) void Thunk_WFSO() {
    __asm {
        push eax
        push ecx
        push edx
        // Stack: [esp]=edx, +4=ecx, +8=eax, +12=ret_addr, +16=hHandle, +20=dwMs
        push dword ptr [esp+20]   // push dwMs
        push dword ptr [esp+16]   // push ret_addr (note +16 because we just pushed dwMs)
        call Recorder_WFSO
        add esp, 8
        pop edx
        pop ecx
        pop eax
        jmp dword ptr [g_origWFSO]
    }
}

// WaitForSingleObjectEx(HANDLE, DWORD dwMs, BOOL) — dwMs at [esp+8] orig
extern "C" __declspec(naked) void Thunk_WFSOEx() {
    __asm {
        push eax
        push ecx
        push edx
        push dword ptr [esp+20]   // dwMs
        push dword ptr [esp+16]   // ret_addr (+16 after one push)
        call Recorder_WFSOEx
        add esp, 8
        pop edx
        pop ecx
        pop eax
        jmp dword ptr [g_origWFSOEx]
    }
}

// WaitForMultipleObjects(DWORD nCount, HANDLE*, BOOL, DWORD dwMs)
//   dwMs at [esp+16] orig (4 args, dwMs is the last)
extern "C" __declspec(naked) void Thunk_WFMO() {
    __asm {
        push eax
        push ecx
        push edx
        // Stack now: +0=edx +4=ecx +8=eax +12=ret_addr +16=nCount +20=handles +24=waitAll +28=dwMs
        push dword ptr [esp+28]   // dwMs
        push dword ptr [esp+16]   // ret_addr (+16 after one push)
        call Recorder_WFMO
        add esp, 8
        pop edx
        pop ecx
        pop eax
        jmp dword ptr [g_origWFMO]
    }
}

bool HookOne(HMODULE mod, const char* name, void* detour, void** ppOrig) {
    FARPROC fn = GetProcAddress(mod, name);
    if (!fn) {
        OD_LOG("[WaitProf] GetProcAddress(%s) failed", name);
        return false;
    }
    MH_STATUS s = MH_CreateHook(reinterpret_cast<LPVOID>(fn), detour, ppOrig);
    if (s != MH_OK) {
        OD_LOG("[WaitProf] CreateHook(%s) failed: %s", name, MH_StatusToString(s));
        return false;
    }
    s = MH_EnableHook(reinterpret_cast<LPVOID>(fn));
    if (s != MH_OK) {
        OD_LOG("[WaitProf] EnableHook(%s) failed: %s", name, MH_StatusToString(s));
        MH_RemoveHook(reinterpret_cast<LPVOID>(fn));
        return false;
    }
    OD_LOG("[WaitProf] Hooked %s @ %p (orig=%p)", name, fn, *ppOrig);
    return true;
}

}  // namespace

bool Install() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        OD_LOG("[WaitProf] GetModuleHandle(kernel32) failed");
        return false;
    }

    HMODULE hTesv = GetModuleHandleW(nullptr);
    if (hTesv) {
        MODULEINFO mi = {};
        if (GetModuleInformation(GetCurrentProcess(), hTesv, &mi, sizeof(mi))) {
            g_tesvBase = reinterpret_cast<uint32_t>(mi.lpBaseOfDll);
            g_tesvEnd  = g_tesvBase + mi.SizeOfImage;
            OD_LOG("[WaitProf] TESV.exe range: 0x%08X..0x%08X", g_tesvBase, g_tesvEnd);
        }
    }
    if (g_tesvBase == 0) { g_tesvBase = 0x00400000; g_tesvEnd = 0x02000000; }

    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
        OD_LOG("[WaitProf] MH_Initialize failed: %s", MH_StatusToString(s));
        return false;
    }

    bool any = false;
    if (HookOne(hKernel32, "WaitForSingleObject",   reinterpret_cast<void*>(Thunk_WFSO),   &g_origWFSO))   any = true;
    if (HookOne(hKernel32, "WaitForSingleObjectEx", reinterpret_cast<void*>(Thunk_WFSOEx), &g_origWFSOEx)) any = true;
    if (HookOne(hKernel32, "WaitForMultipleObjects", reinterpret_cast<void*>(Thunk_WFMO),  &g_origWFMO))   any = true;

    g_lastLog = std::chrono::steady_clock::now();
    return any;
}

void Shutdown() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return;
    auto unhook = [&](const char* name) {
        FARPROC fn = GetProcAddress(hKernel32, name);
        if (fn) {
            MH_DisableHook(reinterpret_cast<LPVOID>(fn));
            MH_RemoveHook(reinterpret_cast<LPVOID>(fn));
        }
    };
    unhook("WaitForSingleObject");
    unhook("WaitForSingleObjectEx");
    unhook("WaitForMultipleObjects");
}

namespace {

void DumpOne(const char* label, const WaitBucket* table,
             uint64_t total, uint64_t fromTesv) {
    if (fromTesv == 0) {
        OD_LOG("[WaitProf] %s: total=%llu (TESV=0)", label,
               (unsigned long long)total);
        return;
    }
    std::vector<WaitBucket> entries;
    entries.reserve(64);
    for (int i = 0; i < kHashSlots; ++i) {
        if (table[i].callerVa != 0) entries.push_back(table[i]);
    }
    std::sort(entries.begin(), entries.end(),
              [](const WaitBucket& a, const WaitBucket& b) {
                  return a.hits > b.hits;
              });
    OD_LOG("[WaitProf] %s: total=%llu (TESV=%llu). Top 10 callers. "
           "call_site_FF15 = ret-6 (FF 15 imm32 indirect). "
           "call_site_FFDx = ret-2 (call reg).",
           label, (unsigned long long)total, (unsigned long long)fromTesv);
    int n = (int)entries.size();
    if (n > 10) n = 10;
    for (int i = 0; i < n; ++i) {
        uint32_t ret = entries[i].callerVa;
        double pct = (100.0 * (double)entries[i].hits) / (double)fromTesv;
        const char* msStr;
        char msBuf[32];
        if (entries[i].lastDwMs == INFINITE) {
            msStr = "INFINITE";
        } else {
            std::snprintf(msBuf, sizeof(msBuf), "%lu", (unsigned long)entries[i].lastDwMs);
            msStr = msBuf;
        }
        OD_LOG("[WaitProf]   %s #%-2d  ret=0x%08X  cs_FF15=0x%08X  cs_FFDx=0x%08X  hits=%llu  %.2f%%  lastDwMs=%s  inf=%llu",
               label, i + 1, ret, ret - 6, ret - 2,
               (unsigned long long)entries[i].hits, pct, msStr,
               (unsigned long long)entries[i].infiniteHits);
    }
}

}  // namespace

void MaybeLogStats() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog);
    if (elapsed.count() < 15000) return;
    g_lastLog = now;

    DumpOne("WFSO",   g_bucketsWFSO,
            g_totalCalls_WFSO.load(std::memory_order_relaxed),
            g_tesvCalls_WFSO.load(std::memory_order_relaxed));
    DumpOne("WFSOEx", g_bucketsWFSOEx,
            g_totalCalls_WFSOEx.load(std::memory_order_relaxed),
            g_tesvCalls_WFSOEx.load(std::memory_order_relaxed));
    DumpOne("WFMO",   g_bucketsWFMO,
            g_totalCalls_WFMO.load(std::memory_order_relaxed),
            g_tesvCalls_WFMO.load(std::memory_order_relaxed));
}

}
