#include "SleepProfiler.h"
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

namespace overdrive::sleepprof {

namespace {

// Hash table of Sleep callers. Each slot stores the caller VA (the
// instruction right after `call ds:Sleep`) and a hit count. The actual
// Sleep call site is `callerVa - 6` (size of `FF 15 imm32` indirect call).
constexpr int kHashSlots = 4096;
struct SleepBucket {
    uint32_t callerVa;     // 0 = empty. This is the RETURN address (call site + 6).
    uint64_t hits;
    DWORD    lastDwMs;     // last value of dwMilliseconds passed in
};
SleepBucket g_buckets[kHashSlots] = {};

std::atomic<uint64_t> g_totalCalls{0};
std::atomic<uint64_t> g_callsFromTesv{0};
std::atomic<uint64_t> g_callsFromOther{0};

// Range of TESV.exe so we can attribute calls and ignore Sleep calls
// originating from other modules (kernel32, our own DLL, etc.).
uint32_t g_tesvBase = 0;
uint32_t g_tesvEnd  = 0;

void* g_origSleep = nullptr;
std::chrono::steady_clock::time_point g_lastLog;

inline uint32_t MixAddr(uint32_t p) {
    p ^= p >> 16; p *= 0x7feb352d;
    p ^= p >> 15; p *= 0x846ca68b;
    p ^= p >> 16; return p;
}

// Called from naked thunk. retAddr is the byte AFTER the `call ds:Sleep`.
extern "C" void __cdecl RecordSleepCaller(uint32_t retAddr, DWORD dwMs) {
    g_totalCalls.fetch_add(1, std::memory_order_relaxed);
    if (retAddr < g_tesvBase || retAddr >= g_tesvEnd) {
        g_callsFromOther.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    g_callsFromTesv.fetch_add(1, std::memory_order_relaxed);

    uint32_t slot = MixAddr(retAddr) & (kHashSlots - 1);
    for (int probe = 0; probe < 32; ++probe) {
        if (g_buckets[slot].callerVa == 0) {
            g_buckets[slot].callerVa = retAddr;
            g_buckets[slot].hits = 1;
            g_buckets[slot].lastDwMs = dwMs;
            return;
        }
        if (g_buckets[slot].callerVa == retAddr) {
            ++g_buckets[slot].hits;
            g_buckets[slot].lastDwMs = dwMs;
            return;
        }
        slot = (slot + 1) & (kHashSlots - 1);
    }
}

// __stdcall void Sleep(DWORD dwMilliseconds) — caller pushes dwMs, callee
// (Sleep) pops it via `ret 4`. Our thunk preserves this exactly: we save
// volatile regs, call the recorder with caller-ret-addr + dwMs, restore,
// then jmp into the original Sleep which performs the ret 4.
extern "C" __declspec(naked) void SleepThunk() {
    __asm {
        // Stack on entry (after the caller's `call ds:Sleep`):
        //   [esp]    = ret address back into caller (TESV.exe instruction
        //              immediately after the call — i.e., call_site_va + 6)
        //   [esp+4]  = arg dwMilliseconds
        push eax                  // save volatile regs we might clobber
        push ecx
        push edx
        // Stack now:
        //   [esp]    = saved edx
        //   [esp+4]  = saved ecx
        //   [esp+8]  = saved eax
        //   [esp+12] = ret_addr_to_caller
        //   [esp+16] = arg dwMs
        push dword ptr [esp+16]   // push dwMs
        push dword ptr [esp+16]   // push ret_addr (note: index shifted by 4 after first push)
        call RecordSleepCaller    // cdecl, we clean
        add esp, 8                // pop our 2 pushed args
        pop edx
        pop ecx
        pop eax
        // Stack restored to entry shape; now chain to original Sleep.
        // Original Sleep will do `ret 4` which pops both ret_addr_to_caller
        // and dwMs, returning control to caller and cleaning the stack.
        jmp dword ptr [g_origSleep]
    }
}

}  // namespace

bool Install() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        OD_LOG("[SleepProf] GetModuleHandle(kernel32) failed");
        return false;
    }
    FARPROC pSleep = GetProcAddress(hKernel32, "Sleep");
    if (!pSleep) {
        OD_LOG("[SleepProf] GetProcAddress(Sleep) failed");
        return false;
    }

    // Capture TESV.exe address range so we can filter to only its callers.
    HMODULE hTesv = GetModuleHandleW(nullptr);  // module handle of host EXE
    if (hTesv) {
        MODULEINFO mi = {};
        if (GetModuleInformation(GetCurrentProcess(), hTesv, &mi, sizeof(mi))) {
            g_tesvBase = reinterpret_cast<uint32_t>(mi.lpBaseOfDll);
            g_tesvEnd  = g_tesvBase + mi.SizeOfImage;
            OD_LOG("[SleepProf] TESV.exe range: 0x%08X..0x%08X", g_tesvBase, g_tesvEnd);
        }
    }
    if (g_tesvBase == 0) {
        OD_LOG("[SleepProf] could not determine TESV.exe range; will record all callers");
        g_tesvBase = 0x00400000;  // typical Skyrim ImageBase
        g_tesvEnd  = 0x02000000;  // generous upper bound
    }

    // MinHook is shared with NiDX9Hooks/D3DXReplace/D3D9Hook; init is idempotent.
    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
        OD_LOG("[SleepProf] MH_Initialize failed: %s", MH_StatusToString(s));
        return false;
    }
    s = MH_CreateHook(reinterpret_cast<LPVOID>(pSleep),
                      reinterpret_cast<LPVOID>(SleepThunk),
                      &g_origSleep);
    if (s != MH_OK) {
        OD_LOG("[SleepProf] MH_CreateHook(Sleep) failed: %s", MH_StatusToString(s));
        return false;
    }
    s = MH_EnableHook(reinterpret_cast<LPVOID>(pSleep));
    if (s != MH_OK) {
        OD_LOG("[SleepProf] MH_EnableHook(Sleep) failed: %s", MH_StatusToString(s));
        MH_RemoveHook(reinterpret_cast<LPVOID>(pSleep));
        return false;
    }
    g_lastLog = std::chrono::steady_clock::now();
    OD_LOG("[SleepProf] Hooked kernel32!Sleep @ %p (orig trampoline=%p)",
           pSleep, g_origSleep);
    return true;
}

void Shutdown() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32) {
        FARPROC pSleep = GetProcAddress(hKernel32, "Sleep");
        if (pSleep) {
            MH_DisableHook(reinterpret_cast<LPVOID>(pSleep));
            MH_RemoveHook(reinterpret_cast<LPVOID>(pSleep));
        }
    }
}

void MaybeLogStats() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog);
    if (elapsed.count() < 15000) return;
    g_lastLog = now;

    const uint64_t total      = g_totalCalls.load(std::memory_order_relaxed);
    const uint64_t fromTesv   = g_callsFromTesv.load(std::memory_order_relaxed);
    const uint64_t fromOther  = g_callsFromOther.load(std::memory_order_relaxed);

    if (fromTesv == 0) {
        OD_LOG("[SleepProf] %.1fs: total=%llu (TESV=%llu, other=%llu) — no TESV Sleep calls yet",
               elapsed.count() / 1000.0,
               (unsigned long long)total,
               (unsigned long long)fromTesv,
               (unsigned long long)fromOther);
        return;
    }

    // Snapshot+sort. Don't reset — these are cumulative because rare-but-hot
    // Sleep callers might not show within a single 15s window.
    std::vector<SleepBucket> entries;
    entries.reserve(256);
    for (int i = 0; i < kHashSlots; ++i) {
        if (g_buckets[i].callerVa != 0) entries.push_back(g_buckets[i]);
    }
    std::sort(entries.begin(), entries.end(),
              [](const SleepBucket& a, const SleepBucket& b) {
                  return a.hits > b.hits;
              });

    OD_LOG("[SleepProf] cumulative: total Sleep calls=%llu (TESV=%llu, other=%llu). "
           "Top 15 TESV callers. call_site_FF15 = ret-6 (call ds:Sleep, indirect imm32). "
           "call_site_FFDx = ret-2 (call reg, e.g. call ebp). Pick the form matching the bytes:",
           (unsigned long long)total,
           (unsigned long long)fromTesv,
           (unsigned long long)fromOther);
    int n = (int)entries.size();
    if (n > 15) n = 15;
    for (int i = 0; i < n; ++i) {
        uint32_t retAddr = entries[i].callerVa;
        double pct = (100.0 * (double)entries[i].hits) / (double)fromTesv;
        OD_LOG("[SleepProf]   #%-2d  ret=0x%08X  call_site_FF15=0x%08X  call_site_FFDx=0x%08X  hits=%llu  %.2f%%  lastDwMs=%lu",
               i + 1, retAddr, retAddr - 6, retAddr - 2,
               (unsigned long long)entries[i].hits, pct,
               (unsigned long)entries[i].lastDwMs);
    }
}

}
