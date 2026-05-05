#include "D3D9ReadProfiler.h"
#include "DebugLogger.h"
#include "CrashDebugger.h"

#include <atomic>
#include <chrono>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <windows.h>

namespace overdrive::readprofiler {

namespace {

const char* kSlotNames[READ_COUNT_] = {
    "GetRenderTarget",
    "GetDepthStencilSurface",
    "GetTransform",
    "GetRenderState",
    "GetTexture",
    "GetSamplerState",
    "GetTextureStageState",
    "GetVertexShader",
    "GetPixelShader",
    "GetStreamSource",
    "GetIndices",
    "GetVertexDeclaration",
    "GetVertexShaderConstantF",
    "GetPixelShaderConstantF",
    "GetViewport",
};

// Open-addressed hash table per slot. Each entry: (retaddr, count).
// 256 slots per table = 4096 total. Plenty for the small number of distinct
// call sites a typical game has per Get* method (usually <30 unique).
constexpr int kHashSlots = 256;

struct Entry {
    volatile LONG retaddr;  // 0 = empty
    volatile LONG count;
};

Entry g_table[READ_COUNT_][kHashSlots] = {};
volatile LONG g_dropped[READ_COUNT_] = {};       // probe overflow
volatile LONG g_totalCalls[READ_COUNT_] = {};

inline uint32_t Mix(uint32_t p) {
    p ^= p >> 16; p *= 0x7feb352d;
    p ^= p >> 15; p *= 0x846ca68b;
    p ^= p >> 16; return p;
}

std::chrono::steady_clock::time_point g_lastLog;
LONG g_lastTotalSnap[READ_COUNT_] = {};

}  // namespace

void Note(SlotId slot, uint32_t retaddr) {
    if (slot >= READ_COUNT_ || retaddr == 0) return;
    InterlockedIncrement(&g_totalCalls[slot]);

    const LONG ra = (LONG)retaddr;
    Entry* tbl = g_table[slot];
    uint32_t i = Mix(retaddr) & (kHashSlots - 1);
    for (int probe = 0; probe < 32; ++probe) {
        const LONG existing = tbl[i].retaddr;
        if (existing == ra) {
            InterlockedIncrement(&tbl[i].count);
            return;
        }
        if (existing == 0) {
            const LONG prev = InterlockedCompareExchange(&tbl[i].retaddr, ra, 0);
            if (prev == 0 || prev == ra) {
                InterlockedIncrement(&tbl[i].count);
                return;
            }
        }
        i = (i + 1) & (kHashSlots - 1);
    }
    InterlockedIncrement(&g_dropped[slot]);
}

void MaybeLogStats() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog);
    if (elapsed.count() < 5000) return;
    g_lastLog = now;

    // Quick check — anything happening at all?
    bool anyActive = false;
    for (int s = 0; s < READ_COUNT_; ++s) {
        if (g_totalCalls[s] != g_lastTotalSnap[s]) { anyActive = true; break; }
    }
    if (!anyActive) return;

    OD_LOG("[ReadProf] D3D9 Get* call-site histogram (top per slot, with "
           "TESV symbol where resolvable):");

    for (int s = 0; s < READ_COUNT_; ++s) {
        const LONG total = g_totalCalls[s];
        const LONG delta = total - g_lastTotalSnap[s];
        g_lastTotalSnap[s] = total;
        if (total == 0) continue;

        // Snapshot non-empty entries and sort.
        struct Hit { LONG retaddr; LONG count; };
        std::vector<Hit> hits;
        hits.reserve(32);
        for (int i = 0; i < kHashSlots; ++i) {
            const LONG ra = g_table[s][i].retaddr;
            const LONG cnt = g_table[s][i].count;
            if (ra != 0 && cnt > 0) hits.push_back({ ra, cnt });
        }
        std::sort(hits.begin(), hits.end(),
                  [](const Hit& a, const Hit& b) { return a.count > b.count; });

        const LONG dropped = g_dropped[s];
        OD_LOG("[ReadProf] %-26s total=%ld (+%ld) sites=%zu dropped=%ld",
               kSlotNames[s], (long)total, (long)delta, hits.size(), (long)dropped);

        const size_t shown = hits.size() < 8 ? hits.size() : 8;
        for (size_t i = 0; i < shown; ++i) {
            const uint32_t ret = (uint32_t)hits[i].retaddr;
            const double pct = total ? (100.0 * hits[i].count / total) : 0.0;

            // Try TESV symbol via the IDA-extracted symbol table that
            // crashdbg builds at install time. Falls back to "?" if the
            // address isn't in TESV.exe's range or no symbol matched.
            char sym[160] = {0};
            unsigned long off = 0;
            const char* nm = crashdbg::ResolveTesvAddr(ret, &off);
            if (nm && nm[0] && nm[0] != '?') {
                std::snprintf(sym, sizeof(sym), "  %s+0x%lX", nm, off);
            }
            // call_site_FF50 = ret-3 (FF 50 NN: 1-byte slot offset)
            // call_site_FF90 = ret-6 (FF 90 NN NN NN NN: 4-byte slot offset)
            // call_site_FFD0 = ret-2 (call eax after preceding mov eax,[reg+disp])
            OD_LOG("[ReadProf]   #%-2zu  ret=0x%08lX  cs_FF50=0x%08lX  "
                   "cs_FF90=0x%08lX  cs_FFD0=0x%08lX  hits=%-8ld  %5.2f%%%s",
                   i + 1, (unsigned long)ret,
                   (unsigned long)(ret - 3),
                   (unsigned long)(ret - 6),
                   (unsigned long)(ret - 2),
                   (long)hits[i].count, pct, sym);
        }
    }
}

}
