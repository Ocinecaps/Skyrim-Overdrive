#include "ScenegraphProfiler.h"
#include "D3D9Hook.h"
#include "NiDX9Hooks.h"
#include "DebugLogger.h"
#include "Globals.h"
#include "CrashDebugger.h"

#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>

namespace overdrive::profiler {

namespace {

// Address ranges from FindCallers.exe heuristic (RET + >=2 CC pad). For
// sub_CA2610 we cap the end at the next vtable slot (0x00CA2A50) since the
// raw heuristic spans past it. Undercounting is the conservative error here:
// if we measure 25% the true value is >= 25%, which only strengthens the
// case for parallelization.
struct Bucket {
    const char* name;
    uint32_t startVa;
    uint32_t endVa;
    std::atomic<uint64_t> count{0};
};

Bucket g_buckets[3] = {
    { "sub_CB7E80", 0x00CB7E80, 0x00CB8765 },   // ~2.2 KB
    { "sub_CA2610", 0x00CA2610, 0x00CA2A50 },   // capped at next vtable slot
    { "sub_B06250", 0x00B06250, 0x00B0635D },   // ~270 B inner helper
};

// Track multiple hot-sub threads. Skyrim uses D3DCREATE_MULTITHREADED so the
// scenegraph walk can hop between threads. Each thunk in NiDX9Hooks writes its
// current tid into g_lastTid_*. We discover up to N distinct tids over time
// and sample each on every tick.
//
// Each tracked thread owns its OWN page-histogram + wait-site-histogram so we
// can attribute samples per-thread (was a single shared hash before). This is
// what lets us answer "is the render thread waiting, or are workers idling?"
// without conflating the two.
constexpr int kMaxTrackedThreads = 8;

// Forward decls of the per-thread hash structures. Definitions follow below.
constexpr int kPageHashSlots     = 16384;
constexpr int kWaitSiteHashSlots = 4096;
struct PageBucket {
    uint32_t pageId;
    uint64_t count;
    uint32_t lastEip;
};
struct WaitSite {
    uint32_t returnAddr;
    uint64_t count;
};

struct TrackedThread {
    DWORD      tid           = 0;
    HANDLE     handle        = nullptr;
    uint64_t   sampleCount   = 0;   // total samples taken on this thread
    uint64_t   lastSampleSnap= 0;   // for periodic delta in [Profiler] line
    PageBucket pageHash[kPageHashSlots] = {};
    WaitSite   waitSites[kWaitSiteHashSlots] = {};
};
TrackedThread g_tracked[kMaxTrackedThreads] = {};

std::atomic<uint64_t> g_totalSamples{0};
std::atomic<uint64_t> g_failedSamples{0};
HANDLE g_samplerThread = nullptr;
std::atomic<bool> g_stopRequested{false};
std::chrono::steady_clock::time_point g_lastLog;
std::chrono::steady_clock::time_point g_lastPageDump;
std::chrono::steady_clock::time_point g_installTime;
uint64_t g_lastBucketSnap[3] = { 0, 0, 0 };
uint64_t g_lastTotalSnap = 0;

// TESV.exe code range — captured at Install. The wait-site sampler walks
// up the suspended thread's stack looking for the first address in this
// range, which is the TESV-internal call site responsible for the wait
// (skipping past the kernel32/KERNELBASE wrapper frames).
uint32_t g_tesvLo = 0;
uint32_t g_tesvHi = 0;

// 30s warmup before recording. Skyrim's first ~30s is menu / loading screen
// which has nothing to do with the actual gameplay bottleneck. Sampling
// during that window pollutes the histogram with menu code that never runs
// during real play. Sampler thread still runs (so SuspendThread is exercised
// and any bugs surface early) but RecordPage / bucket inc are no-ops until
// 30s have elapsed.
constexpr int kWarmupMs = 30000;
std::atomic<bool> g_warmupComplete{false};

// Wait-call-site tracking is now per-thread (TrackedThread::waitSites). When
// sampled EIP is inside a wait function, the value at [esp] is the return
// address into whoever called the wait. Bucketing per-thread lets us tell
// "render thread waiting on GPU" from "worker pool idle".

// Address ranges of the wait functions we want to track. Resolved lazily on
// first dump via SymFromAddr to find the actual VA in this process's ntdll.
// For the sampling check we use a plain bytewise [start, end) test.
struct WaitRange {
    const char* name;
    uint32_t startVa;
    uint32_t endVa;
};
// NtDelayExecution is the syscall behind Sleep(N). Skyrim has 503 Sleep call
// sites in TESV.exe (extracted via IDA, see reference_skyrim_sleep_xrefs.md
// in memory). Many are spinlock-with-yield patterns where Sleep(0) is hit
// thousands of times per second. Tracking NtDelayExecution callers lets us
// cross-reference runtime hits to those 503 VAs and pick the hottest few
// to patch (replace `call Sleep` bytes with `pause; pause; ...`).
WaitRange g_waitRanges[] = {
    { "ZwWaitForSingleObject",    0, 0 },
    { "ZwWaitForMultipleObjects", 0, 0 },
    { "NtWaitForAlertByThreadId", 0, 0 },
    { "NtDelayExecution",         0, 0 },
    { "ZwDelayExecution",         0, 0 },  // alias name some symbol DBs use
};
bool g_waitRangesResolved = false;

inline uint32_t MixAddr(uint32_t p) {
    p ^= p >> 16; p *= 0x7feb352d;
    p ^= p >> 15; p *= 0x846ca68b;
    p ^= p >> 16; return p;
}

inline void RecordWaitSite(TrackedThread* tt, uint32_t returnAddr) {
    if (returnAddr == 0) return;
    uint32_t slot = MixAddr(returnAddr) & (kWaitSiteHashSlots - 1);
    for (int probe = 0; probe < 32; ++probe) {
        if (tt->waitSites[slot].returnAddr == 0) {
            tt->waitSites[slot].returnAddr = returnAddr;
            tt->waitSites[slot].count = 1;
            return;
        }
        if (tt->waitSites[slot].returnAddr == returnAddr) {
            ++tt->waitSites[slot].count;
            return;
        }
        slot = (slot + 1) & (kWaitSiteHashSlots - 1);
    }
}

inline bool IsInWaitFunction(uint32_t eip) {
    for (auto& r : g_waitRanges) {
        if (r.startVa && eip >= r.startVa && eip < r.endVa) return true;
    }
    return false;
}

// Page-histogram is now per-thread (TrackedThread::pageHash). Each tracked
// thread maintains its own 16384-slot open-addressed hash. All accesses on
// the sampler thread; no locks needed.
//
// 4 KB pages → uint32 pageId = eip >> 12.
bool g_symInitialized = false;

inline uint32_t MixPageId(uint32_t p) {
    // Cheap scrambling so consecutive pages don't collide.
    p ^= p >> 16;
    p *= 0x7feb352d;
    p ^= p >> 15;
    p *= 0x846ca68b;
    p ^= p >> 16;
    return p;
}

inline void RecordPage(TrackedThread* tt, uint32_t eip) {
    const uint32_t pid = (eip >> 12) | 1;  // OR 1 so we never see pageId 0
    uint32_t slot = MixPageId(pid) & (kPageHashSlots - 1);
    for (int probe = 0; probe < 64; ++probe) {
        if (tt->pageHash[slot].pageId == 0) {
            tt->pageHash[slot].pageId = pid;
            tt->pageHash[slot].count  = 1;
            tt->pageHash[slot].lastEip = eip;
            return;
        }
        if (tt->pageHash[slot].pageId == pid) {
            ++tt->pageHash[slot].count;
            tt->pageHash[slot].lastEip = eip;  // last-write-wins is fine for a sample
            return;
        }
        slot = (slot + 1) & (kPageHashSlots - 1);
    }
    // Probe overflow — bucket dropped. With 16K slots this should never
    // happen for any realistic code footprint.
}

void EnsureSymbolsInitialized() {
    if (g_symInitialized) return;
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES |
                  SYMOPT_UNDNAME | SYMOPT_FAIL_CRITICAL_ERRORS);
    const char* symPath =
        "srv*C:\\Users\\nro\\AppData\\Local\\Symbols*"
        "https://msdl.microsoft.com/download/symbols";
    if (SymInitialize(GetCurrentProcess(), symPath, TRUE)) {
        g_symInitialized = true;
        OD_LOG("[Profiler] dbghelp symbol resolution enabled");
    } else {
        DWORD err = GetLastError();
        // Error 87 = ERROR_INVALID_PARAMETER, which dbghelp returns when
        // SymInitialize was already called (typically by CrashDebugger).
        // That's the desired state — symbols ARE initialized, just not by us.
        // Treat it as success.
        if (err == ERROR_INVALID_PARAMETER) {
            g_symInitialized = true;
            OD_LOG("[Profiler] dbghelp already initialized by another module — using shared state");
        } else {
            OD_LOG("[Profiler] SymInitialize failed: %lu (page hits will show pageVA only)", err);
        }
    }
}

bool ResolveSymbol(uint32_t eip, char* out, size_t outSize) {
    if (!g_symInitialized) return false;
    char buf[sizeof(SYMBOL_INFO) + 256] = {};
    SYMBOL_INFO* sym = reinterpret_cast<SYMBOL_INFO*>(buf);
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen   = 255;
    DWORD64 disp = 0;
    if (!SymFromAddr(GetCurrentProcess(), (DWORD64)eip, &disp, sym)) return false;
    std::snprintf(out, outSize, "%s+0x%llx", sym->Name, (unsigned long long)disp);
    return true;
}

// Resolve ntdll wait function VAs once, by name, after SymInitialize is up.
// Each function gets a generous 256-byte range (covers the whole function for
// these short syscall wrappers).
void ResolveWaitRanges() {
    if (g_waitRangesResolved) return;
    if (!g_symInitialized) return;
    for (auto& r : g_waitRanges) {
        char buf[sizeof(SYMBOL_INFO) + 256] = {};
        SYMBOL_INFO* sym = reinterpret_cast<SYMBOL_INFO*>(buf);
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen   = 255;
        if (SymFromName(GetCurrentProcess(), r.name, sym)) {
            r.startVa = (uint32_t)sym->Address;
            r.endVa   = r.startVa + 256;
            OD_LOG("[Profiler] wait-range: %s @ 0x%08X..0x%08X",
                   r.name, r.startVa, r.endVa);
        } else {
            OD_LOG("[Profiler] wait-range: %s NOT FOUND (err=%lu)",
                   r.name, GetLastError());
        }
    }
    g_waitRangesResolved = true;
}

struct ModInfo {
    char     name[64];
    uint64_t baseLow;
    uint64_t baseHigh;
};

void EnumerateModules(std::vector<ModInfo>& out) {
    HMODULE mods[512];
    DWORD needed = 0;
    HANDLE proc = GetCurrentProcess();
    if (!EnumProcessModules(proc, mods, sizeof(mods), &needed)) return;
    int n = (int)(needed / sizeof(HMODULE));
    if (n > 512) n = 512;
    for (int i = 0; i < n; ++i) {
        MODULEINFO mi = {};
        if (!GetModuleInformation(proc, mods[i], &mi, sizeof(mi))) continue;
        char path[MAX_PATH] = {};
        if (!GetModuleFileNameExA(proc, mods[i], path, MAX_PATH)) continue;
        const char* slash = std::strrchr(path, '\\');
        const char* base = slash ? slash + 1 : path;
        ModInfo m = {};
        std::snprintf(m.name, sizeof(m.name), "%s", base);
        m.baseLow  = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        m.baseHigh = m.baseLow + mi.SizeOfImage;
        out.push_back(m);
    }
}

const char* ModuleNameForPage(const std::vector<ModInfo>& mods, uint32_t pid) {
    const uint64_t addr = (uint64_t)pid << 12;
    for (auto& m : mods) {
        if (addr >= m.baseLow && addr < m.baseHigh) return m.name;
    }
    return "?";
}

// Walk the candidate tids exposed by NiDX9Hooks (and the captured render-
// thread tid from D3D9Hook) and OpenThread on any new one. Cheap (a few
// reads + a small scan) so safe to call every iteration.
void RefreshTrackedThreads() {
    DWORD candidates[4] = {
        static_cast<DWORD>(nidx9::g_lastTid_CB7E80),
        static_cast<DWORD>(nidx9::g_lastTid_CA2610),
        static_cast<DWORD>(nidx9::g_lastTid_B06250),
        d3d9hook::gRenderThreadId.load(std::memory_order_acquire),
    };
    for (DWORD tid : candidates) {
        if (tid == 0) continue;
        // Already tracked?
        bool already = false;
        for (auto& t : g_tracked) {
            if (t.tid == tid) { already = true; break; }
        }
        if (already) continue;
        // Find a free slot.
        for (auto& t : g_tracked) {
            if (t.tid == 0) {
                HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                      THREAD_QUERY_INFORMATION,
                                      FALSE, tid);
                if (h) {
                    t.tid = tid;
                    t.handle = h;
                    OD_LOG("[Profiler] Now tracking hot-sub thread tid=%lu handle=%p",
                           tid, h);
                } else {
                    OD_LOG("[Profiler] OpenThread(tid=%lu) failed: %lu",
                           tid, GetLastError());
                    // Still record the tid so we don't retry every tick.
                    t.tid = tid;
                    t.handle = nullptr;
                }
                break;
            }
        }
    }
}

// Sample a single thread: suspend, capture EIP, resume, bucket.
// Records into the per-thread page+wait histograms owned by `tt`.
void SampleOne(TrackedThread* tt) {
    HANDLE h = tt->handle;
    if (!h) return;
    DWORD susp = SuspendThread(h);
    if (susp == (DWORD)-1) {
        g_failedSamples.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;  // gives us EIP, ESP, EFlags
    BOOL got = GetThreadContext(h, &ctx);
    DWORD eip = got ? ctx.Eip : 0;
    DWORD esp = got ? ctx.Esp : 0;

    // If sampled EIP is inside a wait syscall stub, scan the stack for the
    // first address that lies in TESV.exe's code range. The chain is:
    //   TESV.exe   →  call ds:WaitForSingleObject       (IAT thunk)
    //   IAT thunk  →  jmp KERNELBASE!WaitForSO          (immediate jmp)
    //   KERNELBASE →  call WaitForSOEx, then ZwWaitForSO
    //   ntdll      →  syscall (where we sample)
    // Reading [esp] gives only the KERNELBASE return — useless for blame.
    // Walk up to 32 stack words; first one in [g_tesvBase, g_tesvEnd) is
    // (with very high probability) the TESV.exe instruction immediately
    // after the actual `call ds:WaitForSingleObject`. That's the call site
    // we want to blame for the wait wall-time.
    //
    // Safety: VirtualQuery confirms the page is readable AND committed AND
    // not a guard page before each dereference. If the suspended thread is
    // holding a heap lock, our query/read won't deadlock (no allocations,
    // no other locks taken).
    DWORD waitReturnAddr = 0;
    if (got && esp != 0 && IsInWaitFunction(eip)) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery((LPCVOID)esp, &mbi, sizeof(mbi)) &&
            mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            // Calculate the safe upper bound for this stack page.
            uintptr_t pageEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            uintptr_t scanEnd = (uintptr_t)esp + 32 * sizeof(DWORD);
            if (scanEnd > pageEnd) scanEnd = pageEnd;

            // First, capture the immediate caller (kernel32/KERNELBASE).
            DWORD kernelCaller = *reinterpret_cast<volatile DWORD*>(esp);

            // Then walk up looking for a TESV.exe address that's plausibly
            // a return address (within 64 KB of a known function start, per
            // our IDA-extraction symbol table). The naive "any value in
            // TESV.exe range" filter accepts stale pointers in .rdata/.data
            // (vtables, strings, globals) which produce nonsense like
            // `sub_106A2FB+0xAC90C5`. CrashDbg::IsTesvCodeAddr handles this.
            DWORD tesvCaller = 0;
            for (uintptr_t p = (uintptr_t)esp; p + 4 <= scanEnd; p += 4) {
                DWORD v = *reinterpret_cast<volatile DWORD*>(p);
                if (v >= g_tesvLo && v < g_tesvHi &&
                    crashdbg::IsTesvCodeAddr(v, 0x10000)) {
                    tesvCaller = v;
                    break;
                }
            }
            // Prefer TESV caller; fall back to kernel caller if not found.
            waitReturnAddr = tesvCaller ? tesvCaller : kernelCaller;
        }
    }

    ResumeThread(h);  // resume IMMEDIATELY after stack read

    if (!got) {
        g_failedSamples.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Warmup gate: count the failed/total but do NOT bucket until 30s elapsed.
    if (!g_warmupComplete.load(std::memory_order_relaxed)) {
        g_totalSamples.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    for (auto& b : g_buckets) {
        if (eip >= b.startVa && eip < b.endVa) {
            b.count.fetch_add(1, std::memory_order_relaxed);
            break;
        }
    }
    RecordPage(tt, eip);
    if (waitReturnAddr) RecordWaitSite(tt, waitReturnAddr);
    ++tt->sampleCount;
    g_totalSamples.fetch_add(1, std::memory_order_relaxed);
}

// Per-thread dump: snapshot+reset this thread's hashes, then log a top-N page
// histogram and top-N wait-site histogram tagged with its tid. Callers who
// don't care about per-thread can compare the lines and aggregate mentally.
void DumpThreadHistograms(TrackedThread& tt,
                          const std::vector<ModInfo>& mods) {
    // Snapshot and reset page hash.
    PageBucket pageSnap[kPageHashSlots];
    std::memcpy(pageSnap, tt.pageHash, sizeof(pageSnap));
    std::memset(tt.pageHash, 0, sizeof(tt.pageHash));

    std::vector<PageBucket> entries;
    entries.reserve(256);
    uint64_t totalSamples = 0;
    for (int i = 0; i < kPageHashSlots; ++i) {
        if (pageSnap[i].pageId != 0) {
            entries.push_back(pageSnap[i]);
            totalSamples += pageSnap[i].count;
        }
    }
    if (entries.empty() || totalSamples == 0) {
        OD_LOG("[Profiler-T%lu] no samples this window", (unsigned long)tt.tid);
        return;
    }
    std::sort(entries.begin(), entries.end(),
              [](const PageBucket& a, const PageBucket& b) {
                  return a.count > b.count;
              });

    OD_LOG("[Profiler-T%lu] page histogram: %llu pages, %llu samples. Top 12:",
           (unsigned long)tt.tid,
           (unsigned long long)entries.size(),
           (unsigned long long)totalSamples);
    int dumpN = (int)entries.size();
    if (dumpN > 12) dumpN = 12;
    for (int i = 0; i < dumpN; ++i) {
        const uint32_t pid    = entries[i].pageId;
        const uint64_t cnt    = entries[i].count;
        const double   pct    = (100.0 * (double)cnt) / (double)totalSamples;
        const uint32_t pageVa = pid << 12;
        const uint32_t eip    = entries[i].lastEip;
        const char* mod = ModuleNameForPage(mods, pid);
        char symbol[320];
        if (ResolveSymbol(eip, symbol, sizeof(symbol))) {
            OD_LOG("[Profiler-T%lu]   #%-2d  page=0x%08X (mod=%s)  hits=%llu  %.2f%%  eip=0x%08X  %s",
                   (unsigned long)tt.tid,
                   i + 1, pageVa, mod, (unsigned long long)cnt, pct, eip, symbol);
        } else {
            OD_LOG("[Profiler-T%lu]   #%-2d  page=0x%08X (mod=%s)  hits=%llu  %.2f%%  eip=0x%08X",
                   (unsigned long)tt.tid,
                   i + 1, pageVa, mod, (unsigned long long)cnt, pct, eip);
        }
    }

    // Wait-site histogram (per-thread). Snapshot+reset.
    WaitSite waitSnap[kWaitSiteHashSlots];
    std::memcpy(waitSnap, tt.waitSites, sizeof(waitSnap));
    std::memset(tt.waitSites, 0, sizeof(tt.waitSites));

    std::vector<WaitSite> waitEntries;
    waitEntries.reserve(64);
    uint64_t waitTotal = 0;
    for (int i = 0; i < kWaitSiteHashSlots; ++i) {
        if (waitSnap[i].returnAddr != 0) {
            waitEntries.push_back(waitSnap[i]);
            waitTotal += waitSnap[i].count;
        }
    }
    if (waitEntries.empty()) return;

    std::sort(waitEntries.begin(), waitEntries.end(),
              [](const WaitSite& a, const WaitSite& b) {
                  return a.count > b.count;
              });
    OD_LOG("[Profiler-T%lu] wait-site histogram: %llu callers, %llu samples (%.1f%% of thread). Top 10:",
           (unsigned long)tt.tid,
           (unsigned long long)waitEntries.size(),
           (unsigned long long)waitTotal,
           (100.0 * (double)waitTotal) / (double)totalSamples);
    int waitN = (int)waitEntries.size();
    if (waitN > 10) waitN = 10;
    for (int i = 0; i < waitN; ++i) {
        const uint32_t ret = waitEntries[i].returnAddr;
        const uint64_t cnt = waitEntries[i].count;
        const double   pct = (100.0 * (double)cnt) / (double)waitTotal;
        const char* mod = ModuleNameForPage(mods, ret >> 12);
        char symbol[320];
        bool resolved = false;
        if (ret >= g_tesvLo && ret < g_tesvHi) {
            unsigned long off = 0;
            const char* nm = crashdbg::ResolveTesvAddr(ret, &off);
            if (nm && nm[0] && nm[0] != '?') {
                std::snprintf(symbol, sizeof(symbol), "%s+0x%lX", nm, off);
                resolved = true;
            }
        }
        if (!resolved) resolved = ResolveSymbol(ret, symbol, sizeof(symbol));
        if (resolved) {
            OD_LOG("[Profiler-T%lu]   wait#%-2d  caller=0x%08X (mod=%s)  hits=%llu  %.2f%%  %s",
                   (unsigned long)tt.tid,
                   i + 1, ret, mod, (unsigned long long)cnt, pct, symbol);
        } else {
            OD_LOG("[Profiler-T%lu]   wait#%-2d  caller=0x%08X (mod=%s)  hits=%llu  %.2f%%",
                   (unsigned long)tt.tid,
                   i + 1, ret, mod, (unsigned long long)cnt, pct);
        }
    }
}

void DumpPageHistogram() {
    EnsureSymbolsInitialized();
    ResolveWaitRanges();

    std::vector<ModInfo> mods;
    EnumerateModules(mods);

    // Identify the captured render thread so its line is annotated. Helpful
    // when scanning the log to find "the render thread".
    DWORD renderTid = d3d9hook::gRenderThreadId.load(std::memory_order_acquire);

    int dumped = 0;
    for (auto& t : g_tracked) {
        if (t.tid == 0) continue;
        const char* tag = (t.tid == renderTid) ? " [render thread]" : "";
        OD_LOG("[Profiler-T%lu]%s --- per-thread histograms ---",
               (unsigned long)t.tid, tag);
        DumpThreadHistograms(t, mods);
        ++dumped;
    }
    if (dumped == 0) {
        OD_LOG("[Profiler] no tracked threads have samples yet");
    }
}

DWORD WINAPI SamplerThreadProc(LPVOID) {
    OD_LOG("[Profiler] sampler thread started tid=%lu (30s warmup before recording)",
           GetCurrentThreadId());

    while (!gShouldExit.load(std::memory_order_relaxed) &&
           !g_stopRequested.load(std::memory_order_relaxed)) {

        Sleep(1);  // ~1 kHz max sampling rate

        // Flip the warmup gate exactly once when 30s have elapsed.
        if (!g_warmupComplete.load(std::memory_order_relaxed)) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - g_installTime).count();
            if (elapsed >= kWarmupMs) {
                g_warmupComplete.store(true, std::memory_order_release);
                // Reset the dump timer so the FIRST histogram covers 30s of
                // real recorded data, not 0s of post-warmup samples.
                g_lastPageDump = now;
                g_lastTotalSnap = g_totalSamples.load(std::memory_order_relaxed);
                OD_LOG("[Profiler] warmup complete (%lldms elapsed). Recording now. "
                       "First histogram dump in 30s.",
                       (long long)elapsed);
            }
        }

        RefreshTrackedThreads();

        // Sample each tracked thread. Each thread's samples land in its own
        // pageHash + waitSites, so DumpPageHistogram can attribute per-thread.
        for (auto& t : g_tracked) {
            if (t.handle) SampleOne(&t);
        }
    }

    // Cleanup tracked thread handles.
    for (auto& t : g_tracked) {
        if (t.handle) CloseHandle(t.handle);
        t.handle = nullptr;
        t.tid = 0;
    }

    OD_LOG("[Profiler] sampler thread exiting (totalSamples=%llu, failed=%llu)",
           (unsigned long long)g_totalSamples.load(),
           (unsigned long long)g_failedSamples.load());
    return 0;
}

}  // namespace

bool Install() {
    // Capture TESV.exe range so the stack-walking wait sampler can identify
    // TESV-internal callers (skipping past kernel32/KERNELBASE frames).
    HMODULE hTesv = GetModuleHandleW(nullptr);
    if (hTesv) {
        MODULEINFO mi = {};
        if (GetModuleInformation(GetCurrentProcess(), hTesv, &mi, sizeof(mi))) {
            g_tesvLo = (uint32_t)(uintptr_t)mi.lpBaseOfDll;
            g_tesvHi = g_tesvLo + mi.SizeOfImage;
        }
    }
    if (g_tesvLo == 0) { g_tesvLo = 0x00400000; g_tesvHi = 0x02000000; }

    // Resolve wait-function VAs at install time, not lazily on first dump.
    // Otherwise IsInWaitFunction returns false for the first 30s+ and the
    // wait-site sampler is silent during the most interesting startup window.
    // SymInitialize is fast (CrashDbg already did it). Wait-range resolution
    // is then a few SymFromName calls — milliseconds.
    EnsureSymbolsInitialized();
    ResolveWaitRanges();

    g_samplerThread = CreateThread(nullptr, 0, SamplerThreadProc, nullptr, 0, nullptr);
    if (!g_samplerThread) {
        OD_LOG("[Profiler] CreateThread failed: %lu", GetLastError());
        return false;
    }
    SetThreadPriority(g_samplerThread, THREAD_PRIORITY_BELOW_NORMAL);
    auto now = std::chrono::steady_clock::now();
    g_lastLog = now;
    g_lastPageDump = now;
    g_installTime = now;
    OD_LOG("[Profiler] Installed. %dms warmup before recording. Will track up to %d hot-sub threads.",
           kWarmupMs, kMaxTrackedThreads);
    return true;
}

void Shutdown() {
    // Final dump on shutdown so we don't lose data if user quits before the
    // next periodic dump fires. Only worth dumping if warmup completed and we
    // have samples; otherwise it's just empty noise.
    if (g_warmupComplete.load(std::memory_order_relaxed)) {
        OD_LOG("[Profiler] shutdown: emitting final histogram before exit");
        DumpPageHistogram();
    }
    g_stopRequested.store(true, std::memory_order_release);
    if (g_samplerThread) {
        WaitForSingleObject(g_samplerThread, 200);
        CloseHandle(g_samplerThread);
        g_samplerThread = nullptr;
    }
}

void MaybeLogStats() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog);
    if (elapsed.count() < 5000) return;
    g_lastLog = now;

    const uint64_t total      = g_totalSamples.load(std::memory_order_relaxed);
    const uint64_t failed     = g_failedSamples.load(std::memory_order_relaxed);
    const uint64_t totalDelta = total - g_lastTotalSnap;
    g_lastTotalSnap = total;

    if (totalDelta == 0) return;

    // Build a compact list of tracked tids for the log line.
    char tidList[128] = {0};
    int tlen = 0;
    for (auto& t : g_tracked) {
        if (t.tid != 0) {
            tlen += std::snprintf(tidList + tlen, sizeof(tidList) - tlen,
                                  "%s%lu", tlen ? "," : "", t.tid);
        }
    }

    char line[768];
    int len = std::snprintf(line, sizeof(line),
        "[Profiler] last %.1fs: %llu samples (%.0f Hz), %llu failed | tracked=[%s] | ",
        elapsed.count() / 1000.0,
        (unsigned long long)totalDelta,
        totalDelta * 1000.0 / elapsed.count(),
        (unsigned long long)failed,
        tidList);

    uint64_t inHotSubs = 0;
    for (int i = 0; i < 3; ++i) {
        const uint64_t c = g_buckets[i].count.load(std::memory_order_relaxed);
        const uint64_t d = c - g_lastBucketSnap[i];
        g_lastBucketSnap[i] = c;
        inHotSubs += d;
        const double pct = (100.0 * (double)d) / (double)totalDelta;
        len += std::snprintf(line + len, sizeof(line) - len,
            "%s=%.1f%% ", g_buckets[i].name, pct);
    }
    const double hotPct = (100.0 * (double)inHotSubs) / (double)totalDelta;
    std::snprintf(line + len, sizeof(line) - len,
        "| HOT_TOTAL=%.1f%%", hotPct);

    OD_LOG("%s", line);

    // Page-histogram dump every 10s (was 30s — too easy to miss when
    // user quits early). Only fires after warmup is complete; the install
    // path resets g_lastPageDump on warmup transition so the first post-
    // warmup dump covers the full 10s of recorded data.
    if (g_warmupComplete.load(std::memory_order_relaxed)) {
        auto pageElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - g_lastPageDump);
        if (pageElapsed.count() >= 10000) {
            g_lastPageDump = now;
            DumpPageHistogram();
        }
    }
}

}
