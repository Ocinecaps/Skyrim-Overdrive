#include "D3DXReplace.h"
#include "DebugLogger.h"
#include "MinHook/MinHook.h"

#include <windows.h>
#include <xmmintrin.h>   // SSE
#include <emmintrin.h>   // SSE2 (for _mm_castps_si128 on some compilers)
#include <cmath>
#include <chrono>

namespace overdrive::d3dx {

std::atomic<uint32_t> gRenderThreadId{0};

std::atomic<uint32_t> gCount_MatrixMultiplyTranspose{0};
std::atomic<uint32_t> gCount_MatrixMultiply{0};
std::atomic<uint32_t> gCount_MatrixTranspose{0};
std::atomic<uint32_t> gCount_Vec3TransformCoord{0};
std::atomic<uint32_t> gCount_Vec3TransformNormal{0};
std::atomic<uint32_t> gCount_Vec3Normalize{0};
std::atomic<uint32_t> gCount_PlaneNormalize{0};

// =============================================================================
// Caller-retaddr histograms — Phase 3 target discovery
// =============================================================================
//
// Every D3DX call has a return address pointing into TESV.exe. Skyrim's
// per-object render-prep loops call D3DX heavily; the dominant retaddr per
// histogram identifies the SKYRIM FUNCTION that's the parallelization target.
//
// Pattern matches NiDX9Hooks's outer-entry retaddr histogram exactly:
//   - 64 lock-free buckets per function (CAS to claim slot, atomic hits)
//   - First match by exact-address wins; otherwise CAS-claim empty slot
//   - Periodic log dumps top entries with hits + percentages
//
// Once we identify the hot caller VA, we read its bytes from TESV memory
// and either disasm with the user's IDA database or directly hook a known-
// shape loop via inline-detour pattern matching. The hot caller IS the
// Phase 3 target — it's the function spending real CPU time looping over
// objects calling D3DX. Replace its loop body with ParallelFor to dispatch
// onto Skyrim's 6-worker pool.

namespace {

constexpr size_t kCallerBuckets = 64;

struct CallerEntry {
    volatile LONG retaddr;   // 0 = empty
    volatile LONG hits;
};

enum CallerSet : int {
    CS_MMT  = 0,   // D3DXMatrixMultiplyTranspose
    CS_MM   = 1,   // D3DXMatrixMultiply
    CS_MT   = 2,   // D3DXMatrixTranspose
    CS_V3TC = 3,   // D3DXVec3TransformCoord
    CS_V3TN = 4,   // D3DXVec3TransformNormal
    CS_V3N  = 5,   // D3DXVec3Normalize
    CS_PN   = 6,   // D3DXPlaneNormalize
    CS_COUNT
};

const char* CallerSetName(int s) {
    switch (s) {
        case CS_MMT:  return "D3DXMatrixMultiplyTranspose";
        case CS_MM:   return "D3DXMatrixMultiply";
        case CS_MT:   return "D3DXMatrixTranspose";
        case CS_V3TC: return "D3DXVec3TransformCoord";
        case CS_V3TN: return "D3DXVec3TransformNormal";
        case CS_V3N:  return "D3DXVec3Normalize";
        case CS_PN:   return "D3DXPlaneNormalize";
    }
    return "?";
}

CallerEntry g_callers[CS_COUNT][kCallerBuckets] = {};
volatile LONG g_callerDropped[CS_COUNT] = {};

inline void NoteCaller(int set, DWORD retaddr) {
    // Latch the render TID once. D3DX is called from the render thread
    // essentially exclusively, so the first thread we see here is it.
    if (gRenderThreadId.load(std::memory_order_relaxed) == 0) {
        gRenderThreadId.store(GetCurrentThreadId(), std::memory_order_relaxed);
    }
    const LONG ra = (LONG)retaddr;
    auto* buckets = g_callers[set];
    for (size_t i = 0; i < kCallerBuckets; ++i) {
        const LONG existing = buckets[i].retaddr;
        if (existing == ra) {
            InterlockedIncrement(&buckets[i].hits);
            return;
        }
        if (existing == 0) {
            const LONG prev = InterlockedCompareExchange(&buckets[i].retaddr, ra, 0);
            if (prev == 0) {
                InterlockedIncrement(&buckets[i].hits);
                return;
            }
            if (prev == ra) {
                InterlockedIncrement(&buckets[i].hits);
                return;
            }
        }
    }
    InterlockedIncrement(&g_callerDropped[set]);
}

}  // namespace

namespace {

// Minimal D3DX type definitions — layout matches Microsoft headers exactly.
// We avoid pulling in d3dx9math.h so the build doesn't need DirectX SDK.
struct D3DXMATRIX_t  { float m[4][4]; };          // 64 bytes, row-major float[4][4]
struct D3DXVECTOR2_t { float x, y; };             // 8 bytes
struct D3DXVECTOR3_t { float x, y, z; };          // 12 bytes — NOT 16! cannot _mm_storeu_ps directly
struct D3DXVECTOR4_t { float x, y, z, w; };       // 16 bytes
struct D3DXPLANE_t   { float a, b, c, d; };       // 16 bytes (same layout as VECTOR4)

// Function-pointer typedefs for trampolines (for completeness; we currently
// don't call originals because our SSE versions are full replacements).
using PFN_MMT  = D3DXMATRIX_t*  (WINAPI*)(D3DXMATRIX_t*, const D3DXMATRIX_t*, const D3DXMATRIX_t*);
using PFN_MM   = D3DXMATRIX_t*  (WINAPI*)(D3DXMATRIX_t*, const D3DXMATRIX_t*, const D3DXMATRIX_t*);
using PFN_MT   = D3DXMATRIX_t*  (WINAPI*)(D3DXMATRIX_t*, const D3DXMATRIX_t*);
using PFN_V3TC = D3DXVECTOR3_t* (WINAPI*)(D3DXVECTOR3_t*, const D3DXVECTOR3_t*, const D3DXMATRIX_t*);
using PFN_V3TN = D3DXVECTOR3_t* (WINAPI*)(D3DXVECTOR3_t*, const D3DXVECTOR3_t*, const D3DXMATRIX_t*);
using PFN_V3N  = D3DXVECTOR3_t* (WINAPI*)(D3DXVECTOR3_t*, const D3DXVECTOR3_t*);
using PFN_PN   = D3DXPLANE_t*   (WINAPI*)(D3DXPLANE_t*, const D3DXPLANE_t*);

PFN_MMT  g_origMMT  = nullptr;
PFN_MM   g_origMM   = nullptr;
PFN_MT   g_origMT   = nullptr;
PFN_V3TC g_origV3TC = nullptr;
PFN_V3TN g_origV3TN = nullptr;
PFN_V3N  g_origV3N  = nullptr;
PFN_PN   g_origPN   = nullptr;

// ---------- SSE helpers ----------

// 4×4 multiply: result = M1 * M2. Stores 4 result rows back, no transpose.
inline void SSEMul4x4(__m128 outRows[4], const D3DXMATRIX_t* m1, const D3DXMATRIX_t* m2) {
    const __m128 m2r0 = _mm_loadu_ps(&m2->m[0][0]);
    const __m128 m2r1 = _mm_loadu_ps(&m2->m[1][0]);
    const __m128 m2r2 = _mm_loadu_ps(&m2->m[2][0]);
    const __m128 m2r3 = _mm_loadu_ps(&m2->m[3][0]);
    for (int r = 0; r < 4; ++r) {
        const __m128 m1r = _mm_loadu_ps(&m1->m[r][0]);
        __m128 acc = _mm_mul_ps(_mm_shuffle_ps(m1r, m1r, _MM_SHUFFLE(0,0,0,0)), m2r0);
        acc = _mm_add_ps(acc, _mm_mul_ps(_mm_shuffle_ps(m1r, m1r, _MM_SHUFFLE(1,1,1,1)), m2r1));
        acc = _mm_add_ps(acc, _mm_mul_ps(_mm_shuffle_ps(m1r, m1r, _MM_SHUFFLE(2,2,2,2)), m2r2));
        acc = _mm_add_ps(acc, _mm_mul_ps(_mm_shuffle_ps(m1r, m1r, _MM_SHUFFLE(3,3,3,3)), m2r3));
        outRows[r] = acc;
    }
}

// ---------- Replacement implementations ----------

extern "C" D3DXMATRIX_t* WINAPI Replace_D3DXMatrixMultiplyTranspose(
    D3DXMATRIX_t* pOut, const D3DXMATRIX_t* pM1, const D3DXMATRIX_t* pM2) {
    NoteCaller(CS_MMT, (DWORD)(uintptr_t)_ReturnAddress()); gCount_MatrixMultiplyTranspose.fetch_add(1, std::memory_order_relaxed);
    if (!pOut || !pM1 || !pM2) return g_origMMT ? g_origMMT(pOut, pM1, pM2) : pOut;

    __m128 rows[4];
    SSEMul4x4(rows, pM1, pM2);
    _MM_TRANSPOSE4_PS(rows[0], rows[1], rows[2], rows[3]);
    _mm_storeu_ps(&pOut->m[0][0], rows[0]);
    _mm_storeu_ps(&pOut->m[1][0], rows[1]);
    _mm_storeu_ps(&pOut->m[2][0], rows[2]);
    _mm_storeu_ps(&pOut->m[3][0], rows[3]);
    return pOut;
}

extern "C" D3DXMATRIX_t* WINAPI Replace_D3DXMatrixMultiply(
    D3DXMATRIX_t* pOut, const D3DXMATRIX_t* pM1, const D3DXMATRIX_t* pM2) {
    NoteCaller(CS_MM, (DWORD)(uintptr_t)_ReturnAddress()); gCount_MatrixMultiply.fetch_add(1, std::memory_order_relaxed);
    if (!pOut || !pM1 || !pM2) return g_origMM ? g_origMM(pOut, pM1, pM2) : pOut;

    __m128 rows[4];
    SSEMul4x4(rows, pM1, pM2);
    _mm_storeu_ps(&pOut->m[0][0], rows[0]);
    _mm_storeu_ps(&pOut->m[1][0], rows[1]);
    _mm_storeu_ps(&pOut->m[2][0], rows[2]);
    _mm_storeu_ps(&pOut->m[3][0], rows[3]);
    return pOut;
}

extern "C" D3DXMATRIX_t* WINAPI Replace_D3DXMatrixTranspose(
    D3DXMATRIX_t* pOut, const D3DXMATRIX_t* pM) {
    NoteCaller(CS_MT, (DWORD)(uintptr_t)_ReturnAddress()); gCount_MatrixTranspose.fetch_add(1, std::memory_order_relaxed);
    if (!pOut || !pM) return g_origMT ? g_origMT(pOut, pM) : pOut;

    __m128 r0 = _mm_loadu_ps(&pM->m[0][0]);
    __m128 r1 = _mm_loadu_ps(&pM->m[1][0]);
    __m128 r2 = _mm_loadu_ps(&pM->m[2][0]);
    __m128 r3 = _mm_loadu_ps(&pM->m[3][0]);
    _MM_TRANSPOSE4_PS(r0, r1, r2, r3);
    _mm_storeu_ps(&pOut->m[0][0], r0);
    _mm_storeu_ps(&pOut->m[1][0], r1);
    _mm_storeu_ps(&pOut->m[2][0], r2);
    _mm_storeu_ps(&pOut->m[3][0], r3);
    return pOut;
}

// Vec3 * Mat4 + perspective divide.
//   r = (v.x*M0 + v.y*M1 + v.z*M2 + M3)
//   out = r.xyz / r.w
extern "C" D3DXVECTOR3_t* WINAPI Replace_D3DXVec3TransformCoord(
    D3DXVECTOR3_t* pOut, const D3DXVECTOR3_t* pV, const D3DXMATRIX_t* pM) {
    NoteCaller(CS_V3TC, (DWORD)(uintptr_t)_ReturnAddress()); gCount_Vec3TransformCoord.fetch_add(1, std::memory_order_relaxed);
    if (!pOut || !pV || !pM) return g_origV3TC ? g_origV3TC(pOut, pV, pM) : pOut;

    const __m128 row0 = _mm_loadu_ps(&pM->m[0][0]);
    const __m128 row1 = _mm_loadu_ps(&pM->m[1][0]);
    const __m128 row2 = _mm_loadu_ps(&pM->m[2][0]);
    const __m128 row3 = _mm_loadu_ps(&pM->m[3][0]);
    __m128 res = _mm_add_ps(
        _mm_add_ps(_mm_mul_ps(row0, _mm_set1_ps(pV->x)),
                   _mm_mul_ps(row1, _mm_set1_ps(pV->y))),
        _mm_add_ps(_mm_mul_ps(row2, _mm_set1_ps(pV->z)),
                   row3));
    // Extract; do scalar divide for w (matches D3DX precision better than rcp_ps).
    alignas(16) float r[4];
    _mm_store_ps(r, res);
    const float invW = 1.0f / r[3];
    pOut->x = r[0] * invW;
    pOut->y = r[1] * invW;
    pOut->z = r[2] * invW;
    return pOut;
}

// Vec3 * 3×3 portion of Mat4 (no translation, no W).
extern "C" D3DXVECTOR3_t* WINAPI Replace_D3DXVec3TransformNormal(
    D3DXVECTOR3_t* pOut, const D3DXVECTOR3_t* pV, const D3DXMATRIX_t* pM) {
    NoteCaller(CS_V3TN, (DWORD)(uintptr_t)_ReturnAddress()); gCount_Vec3TransformNormal.fetch_add(1, std::memory_order_relaxed);
    if (!pOut || !pV || !pM) return g_origV3TN ? g_origV3TN(pOut, pV, pM) : pOut;

    const __m128 row0 = _mm_loadu_ps(&pM->m[0][0]);
    const __m128 row1 = _mm_loadu_ps(&pM->m[1][0]);
    const __m128 row2 = _mm_loadu_ps(&pM->m[2][0]);
    __m128 res =
        _mm_add_ps(_mm_add_ps(_mm_mul_ps(row0, _mm_set1_ps(pV->x)),
                              _mm_mul_ps(row1, _mm_set1_ps(pV->y))),
                              _mm_mul_ps(row2, _mm_set1_ps(pV->z)));
    alignas(16) float r[4];
    _mm_store_ps(r, res);
    pOut->x = r[0];
    pOut->y = r[1];
    pOut->z = r[2];
    return pOut;
}

extern "C" D3DXVECTOR3_t* WINAPI Replace_D3DXVec3Normalize(
    D3DXVECTOR3_t* pOut, const D3DXVECTOR3_t* pV) {
    NoteCaller(CS_V3N, (DWORD)(uintptr_t)_ReturnAddress()); gCount_Vec3Normalize.fetch_add(1, std::memory_order_relaxed);
    if (!pOut || !pV) return g_origV3N ? g_origV3N(pOut, pV) : pOut;

    const float x = pV->x;
    const float y = pV->y;
    const float z = pV->z;
    const float lenSq = x*x + y*y + z*z;
    if (lenSq > 0.0f) {
        // Use scalar sqrt for D3DX precision parity. _mm_rsqrt_ps is faster
        // but only ~12-bit accurate, which can cause subtle visual artifacts
        // in lighting/normal calculations.
        const float invLen = 1.0f / sqrtf(lenSq);
        pOut->x = x * invLen;
        pOut->y = y * invLen;
        pOut->z = z * invLen;
    } else {
        pOut->x = 0.0f;
        pOut->y = 0.0f;
        pOut->z = 0.0f;
    }
    return pOut;
}

// Plane normalize: scale all 4 components so the (a,b,c) normal becomes
// unit length. D matches accordingly so the plane equation is preserved.
extern "C" D3DXPLANE_t* WINAPI Replace_D3DXPlaneNormalize(
    D3DXPLANE_t* pOut, const D3DXPLANE_t* pP) {
    NoteCaller(CS_PN, (DWORD)(uintptr_t)_ReturnAddress()); gCount_PlaneNormalize.fetch_add(1, std::memory_order_relaxed);
    if (!pOut || !pP) return g_origPN ? g_origPN(pOut, pP) : pOut;

    const float a = pP->a, b = pP->b, c = pP->c, d = pP->d;
    const float lenSq = a*a + b*b + c*c;
    if (lenSq > 0.0f) {
        const float invLen = 1.0f / sqrtf(lenSq);
        pOut->a = a * invLen;
        pOut->b = b * invLen;
        pOut->c = c * invLen;
        pOut->d = d * invLen;
    } else {
        pOut->a = pOut->b = pOut->c = pOut->d = 0.0f;
    }
    return pOut;
}

// ---------- Install table ----------

struct ReplaceEntry {
    const char*          name;
    LPVOID               detour;
    LPVOID*              trampolineSlot;
    std::atomic<uint32_t>* counter;
    uint64_t             snapAtLastLog;
};

ReplaceEntry g_table[] = {
    { "D3DXMatrixMultiplyTranspose", (LPVOID)Replace_D3DXMatrixMultiplyTranspose, (LPVOID*)&g_origMMT,  &gCount_MatrixMultiplyTranspose, 0 },
    { "D3DXMatrixMultiply",          (LPVOID)Replace_D3DXMatrixMultiply,          (LPVOID*)&g_origMM,   &gCount_MatrixMultiply,          0 },
    { "D3DXMatrixTranspose",         (LPVOID)Replace_D3DXMatrixTranspose,         (LPVOID*)&g_origMT,   &gCount_MatrixTranspose,         0 },
    { "D3DXVec3TransformCoord",      (LPVOID)Replace_D3DXVec3TransformCoord,      (LPVOID*)&g_origV3TC, &gCount_Vec3TransformCoord,      0 },
    { "D3DXVec3TransformNormal",     (LPVOID)Replace_D3DXVec3TransformNormal,     (LPVOID*)&g_origV3TN, &gCount_Vec3TransformNormal,     0 },
    { "D3DXVec3Normalize",           (LPVOID)Replace_D3DXVec3Normalize,           (LPVOID*)&g_origV3N,  &gCount_Vec3Normalize,           0 },
    { "D3DXPlaneNormalize",          (LPVOID)Replace_D3DXPlaneNormalize,          (LPVOID*)&g_origPN,   &gCount_PlaneNormalize,          0 },
};

std::chrono::steady_clock::time_point g_lastLog;

}  // namespace

bool Install() {
    MH_STATUS s = MH_Initialize();
    if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
        OD_LOG("[D3DX] MH_Initialize failed: %s", MH_StatusToString(s));
        return false;
    }

    int installed = 0;
    for (auto& e : g_table) {
        LPVOID target = nullptr;
        s = MH_CreateHookApiEx(L"d3dx9_42", e.name, e.detour, e.trampolineSlot, &target);
        if (s != MH_OK) {
            OD_LOG("[D3DX] CreateHookApiEx(%s) failed: %s", e.name, MH_StatusToString(s));
            continue;
        }
        s = MH_EnableHook(target);
        if (s != MH_OK) {
            OD_LOG("[D3DX] EnableHook(%s) failed: %s", e.name, MH_StatusToString(s));
            MH_RemoveHook(target);
            continue;
        }
        OD_LOG("[D3DX] Replaced %s @ %p (orig kept @ %p) — SSE", e.name, target, *e.trampolineSlot);
        ++installed;
    }

    g_lastLog = std::chrono::steady_clock::now();
    if (installed == 0) {
        OD_LOG("[D3DX] No replacements installed — d3dx9_42.dll may not be loaded yet");
        return false;
    }
    OD_LOG("[D3DX] Install OK: %d/%zu functions replaced. Stats every 5s.",
           installed, sizeof(g_table) / sizeof(g_table[0]));
    return true;
}

void MaybeLogStats() {
    const auto now     = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog);
    if (elapsed.count() < 5000) return;
    g_lastLog = now;

    const double secs = elapsed.count() / 1000.0;

    // One concise summary line covering all replaced functions.
    char line[1024];
    int  off = 0;
    off += snprintf(line + off, sizeof(line) - off, "[D3DX] last %.1fs:", secs);
    for (auto& e : g_table) {
        const uint64_t cur = e.counter->load(std::memory_order_relaxed);
        const uint64_t d   = cur - e.snapAtLastLog;
        e.snapAtLastLog = cur;
        // Keep names short in the log line — strip the "D3DX" prefix.
        const char* shortName = e.name + 4;
        off += snprintf(line + off, sizeof(line) - off,
                        " %s=%llu(+%.0f/s)",
                        shortName, (unsigned long long)cur, (double)d / secs);
        if (off >= (int)sizeof(line) - 64) break;
    }
    OD_LOG("%s", line);
}

// =============================================================================
// LogCallerHistograms — Phase 3 target discovery dump
// =============================================================================
//
// Periodically logs the top return addresses for each replaced D3DX function.
// Each retaddr is a TESV.exe VA pointing to the instruction RIGHT AFTER the
// `call D3DX...` — the dominant retaddr per function identifies the Skyrim
// function that's calling D3DX in a hot loop.
//
// The hottest retaddr across all functions IS THE PHASE 3 TARGET. That
// Skyrim function's body has a per-frame loop iterating over independent
// objects calling D3DX math. We patch THAT function's loop to use
// ParallelFor instead of running iterations sequentially.

std::chrono::steady_clock::time_point g_lastCallerLog;
bool g_callerHeaderLogged = false;

void MaybeLogCallerHistograms() {
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastCallerLog);
    if (elapsed.count() < 10000) return;   // 10 second cadence — less spam than stats
    g_lastCallerLog = now;

    if (!g_callerHeaderLogged) {
        OD_LOG("[D3DX-Callers] Phase 3 target discovery: top return addresses "
               "per replaced D3DX function. The hottest unique retaddr is the "
               "Skyrim function we patch with ParallelFor.");
        g_callerHeaderLogged = true;
    }

    for (int s = 0; s < CS_COUNT; ++s) {
        // Find top 3 callers for this function.
        struct Top { LONG retaddr; LONG hits; };
        Top top[3] = { {0,0}, {0,0}, {0,0} };
        LONG totalHits = 0;
        int unique = 0;
        for (size_t i = 0; i < kCallerBuckets; ++i) {
            const LONG ra = g_callers[s][i].retaddr;
            const LONG h  = g_callers[s][i].hits;
            if (ra == 0) continue;
            ++unique;
            totalHits += h;
            for (int t = 0; t < 3; ++t) {
                if (h > top[t].hits) {
                    for (int k = 2; k > t; --k) top[k] = top[k-1];
                    top[t] = { ra, h };
                    break;
                }
            }
        }
        if (totalHits == 0) continue;
        OD_LOG("[D3DX-Callers] %s: %d unique callers, %ld total hits, %ld dropped",
               CallerSetName(s), unique, totalHits,
               (long)g_callerDropped[s]);
        for (int t = 0; t < 3; ++t) {
            if (top[t].hits == 0) break;
            const double pct = 100.0 * (double)top[t].hits / (double)totalHits;
            // The actual call instruction is at ret-5 (E8 imm32 = 5 bytes for
            // a relative CALL) for direct calls, or ret-6 (FF 15 mem32 = 6
            // bytes for indirect CALL through a function pointer slot —
            // D3DX9 functions are typically called this way through the IAT).
            OD_LOG("[D3DX-Callers]   #%d  ret=0x%08X  cs_E8=0x%08X  cs_FF15=0x%08X  hits=%ld  %.2f%%",
                   t + 1,
                   (unsigned)top[t].retaddr,
                   (unsigned)(top[t].retaddr - 5),
                   (unsigned)(top[t].retaddr - 6),
                   top[t].hits, pct);
        }
    }
}

}  // namespace overdrive::d3dx
