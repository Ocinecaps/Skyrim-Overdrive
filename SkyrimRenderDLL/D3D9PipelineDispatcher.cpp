#include "D3D9PipelineDispatcher.h"
#include "D3D9Replay.h"
#include "DebugLogger.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <windows.h>
#include <d3d9.h>

namespace overdrive::pipeline {

namespace {

using overdrive::replay::Buffer;
using overdrive::replay::Record;
using overdrive::replay::Op;

// =============================================================================
// State
// =============================================================================

// Two ping-pong buffers. At any moment one is being recorded by T_record and
// the other (or none) is being drained by T_dispatch. Pointers swap at the
// Present boundary.
Buffer  g_bufferA;
Buffer  g_bufferB;
Buffer* g_recordBuffer   = &g_bufferA;
Buffer* g_dispatchBuffer = &g_bufferB;

// Buffer mutex — protects g_recordBuffer's contents AND the swap operation.
// Why: Skyrim runs D3DCREATE_MULTITHREADED (flags=0x54). The render thread
// (Present caller) and the main thread BOTH issue D3D9 Set/Draw via the same
// device pointer. Per the per-thread VkQ slot log, slot[0]=tid_render and
// slot[1]=tid_main both push tens of thousands of records per second. Without
// this lock, std::vector::push_back races corrupt the record stream → wrong
// opcodes / wrong args → visual glitches when DoReplay runs garbage. The lock
// is taken inside each Enqueue* (covers AppendPayload+AppendRecord atomically)
// and around the Flush()/swap. Dispatcher does not need the lock because the
// swap transfers buffer ownership: between swaps, g_dispatchBuffer is touched
// only by T_dispatch.
std::mutex g_bufferMutex;

// Thread + lifecycle.
HANDLE  g_dispatchThread = nullptr;
DWORD   g_dispatchTid    = 0;
HANDLE  g_startEvent     = nullptr;  // signaled when dispatch buffer is ready
HANDLE  g_doneEvent      = nullptr;  // signaled when dispatch buffer drained
std::atomic<bool> g_running{false};
std::atomic<bool> g_installed{false};

// =============================================================================
// State shadow — current-RT/DS as seen by the queued (not-yet-dispatched) ops
// =============================================================================
//
// Refcount-aware: each shadow entry holds one AddRef on the surface it points
// at, so the surface stays alive even if the app Releases its own ref before
// the dispatcher applies the corresponding orig<SetRenderTarget>. On
// Mirror_GetRenderTarget, we AddRef again and return the pointer — the
// caller's eventual Release pairs with our AddRef.
//
// Mutex-protected because EnqueueSetRT/SetDS happens on T_record but
// GetShadow* can be called by any thread doing Mirror_Get*.

std::mutex          g_shadowMutex;
IDirect3DSurface9*  g_shadowRT[kMaxShadowRenderTargets] = {};
IDirect3DSurface9*  g_shadowDS = nullptr;

// Stage 5 — resource-lifetime shadows. Same pattern: AddRef the new resource
// when it's bound (Set), Release when replaced. Without these, app `Release`
// on a still-queued resource lets refcount drop to 0 → dispatcher dispatches
// orig<Set...>() into a destroyed object → crashes or undefined draws (often
// observed as wrong shaders / wrong textures / lighting glitches with no
// hard crash, since D3D9 may tolerate some dangling pointers).
//
// 8 sampler stages for textures, 16 vertex streams. D3D9 spec maxima.
constexpr uint32_t kMaxShadowSamplers = 8;
constexpr uint32_t kMaxShadowStreams  = 16;
IDirect3DBaseTexture9*       g_shadowTex[kMaxShadowSamplers] = {};
IDirect3DVertexShader9*      g_shadowVS = nullptr;
IDirect3DPixelShader9*       g_shadowPS = nullptr;
IDirect3DVertexBuffer9*      g_shadowVB[kMaxShadowStreams]   = {};
IDirect3DIndexBuffer9*       g_shadowIB = nullptr;
IDirect3DVertexDeclaration9* g_shadowVDecl = nullptr;

// Generic refcounted slot replacement. T must have AddRef/Release (i.e. be
// IUnknown-derived). Caller holds g_shadowMutex.
template <typename T>
inline void ShadowReplaceLocked(T*& slot, T* newPtr) {
    if (slot == newPtr) return;
    if (newPtr) newPtr->AddRef();
    T* oldPtr = slot;
    slot = newPtr;
    if (oldPtr) oldPtr->Release();
}

// =============================================================================
// LIFETIME OWNERSHIP — each buffer record holds the AddRef
// =============================================================================
//
// Earlier design (pre-fix): shadow held the AddRef, releasing the previous
// shadow value when a new Set replaced it. This had a race:
//
//   App: SetTexture(0, A)  → shadow AddRef A; record stores A ptr
//   App: SetTexture(0, B)  → shadow Release A, AddRef B; record stores B ptr
//   App: A->Release()       → A's refcount hits 0 → A destroyed
//   Dispatcher (later): orig<SetTexture>(0, A) from buffer record → CRASH
//
// The buffer record is still in the queue holding A's RAW pointer when the
// shadow released it. Dangling pointer dispatch → crash + visual glitches
// (D3D9 silently accepts dangling ptrs sometimes, with garbage results).
//
// FIX: ownership moves to the buffer record. EnqueueSet* AddRefs on enqueue;
// DoReplay's case for that op Releases AFTER calling orig<>(). The resource
// is guaranteed alive between Enqueue and Dispatch. The shadow is now a
// raw-pointer read-cache used only by Mirror_GetRT/GetDS for read coherence
// — it relies on the buffer-record's AddRef to keep the pointer alive while
// the latest SetRT is queued. After dispatch, D3D9's internal ref on the
// bound RT keeps it alive, so the shadow pointer remains safe to AddRef.

// Raw-pointer shadow updaters (no AddRef/Release here — buffer record owns
// the ref now). Locked because Mirror_GetRT can read concurrently.
inline void ShadowSetRT(uint32_t index, IDirect3DSurface9* newSurf) {
    if (index >= kMaxShadowRenderTargets) return;
    std::lock_guard<std::mutex> lk(g_shadowMutex);
    g_shadowRT[index] = newSurf;
}
inline void ShadowSetDS(IDirect3DSurface9* newSurf) {
    std::lock_guard<std::mutex> lk(g_shadowMutex);
    g_shadowDS = newSurf;
}
inline void ShadowSetTex(uint32_t stage, IDirect3DBaseTexture9* newTex) {
    if (stage >= kMaxShadowSamplers) return;
    std::lock_guard<std::mutex> lk(g_shadowMutex);
    g_shadowTex[stage] = newTex;
}
inline void ShadowSetVS(IDirect3DVertexShader9* newShader) {
    std::lock_guard<std::mutex> lk(g_shadowMutex);
    g_shadowVS = newShader;
}
inline void ShadowSetPS(IDirect3DPixelShader9* newShader) {
    std::lock_guard<std::mutex> lk(g_shadowMutex);
    g_shadowPS = newShader;
}
inline void ShadowSetVB(uint32_t stream, IDirect3DVertexBuffer9* newVB) {
    if (stream >= kMaxShadowStreams) return;
    std::lock_guard<std::mutex> lk(g_shadowMutex);
    g_shadowVB[stream] = newVB;
}
inline void ShadowSetIB(IDirect3DIndexBuffer9* newIB) {
    std::lock_guard<std::mutex> lk(g_shadowMutex);
    g_shadowIB = newIB;
}
inline void ShadowSetVDecl(IDirect3DVertexDeclaration9* newDecl) {
    std::lock_guard<std::mutex> lk(g_shadowMutex);
    g_shadowVDecl = newDecl;
}

// AddRef a resource on enqueue. Buffer record owns the ref until DoReplay
// (in D3D9Mirror.cpp) Releases after orig<>(). Used by all resource-bearing
// EnqueueSet* — the AddRef pins the object alive across the
// Enqueue→Dispatch latency window even if the app Releases its own ref.
inline void RecordAddRef(IUnknown* p) { if (p) p->AddRef(); }

// Stats.
std::atomic<uint32_t> g_statFramesEnqueued{0};
std::atomic<uint32_t> g_statFramesDrained{0};
std::atomic<uint32_t> g_statRecordsEnq{0};
std::atomic<uint32_t> g_statRecordsDrained{0};
std::atomic<uint32_t> g_statFlushes{0};
std::atomic<uint32_t> g_statBufferSwapWaits{0};

std::chrono::steady_clock::time_point g_lastLog;

// =============================================================================
// Dispatcher thread
// =============================================================================
//
// Loop:
//   1. Wait on g_startEvent.
//   2. Replay g_dispatchBuffer through the existing replay::Replay() function
//      (which goes through DoReplay in D3D9Mirror.cpp's anon namespace,
//      which calls orig<>() against the real D3D9 device).
//   3. Clear g_dispatchBuffer (we own this buffer until next swap).
//   4. Signal g_doneEvent.
//
// IMPORTANT: g_dispatchBuffer pointer must NOT be touched by T_record while
// the dispatcher is processing it. The Present-boundary swap protocol enforces
// this: T_record always WaitForSingleObject(g_doneEvent) before swapping.

DWORD WINAPI DispatchThreadProc(LPVOID) {
    g_dispatchTid = GetCurrentThreadId();
    OD_LOG("[Pipeline] dispatcher thread started tid=%lu", g_dispatchTid);

    while (g_running.load(std::memory_order_acquire)) {
        // Wait for a buffer to be ready. INFINITE — but Shutdown() sets
        // g_running=false and SetEvent(g_startEvent) so we wake.
        DWORD wr = WaitForSingleObject(g_startEvent, INFINITE);
        if (wr != WAIT_OBJECT_0) continue;
        if (!g_running.load(std::memory_order_acquire)) break;

        Buffer* buf = g_dispatchBuffer;
        if (buf && !buf->records.empty()) {
            IDirect3DDevice9* dev = overdrive::replay::GetDevice();
            if (dev) {
                overdrive::replay::Replay(dev, *buf);
                g_statRecordsDrained.fetch_add(
                    static_cast<uint32_t>(buf->records.size()),
                    std::memory_order_relaxed);
            }
        }
        if (buf) buf->Clear();

        g_statFramesDrained.fetch_add(1, std::memory_order_relaxed);
        SetEvent(g_doneEvent);
    }

    OD_LOG("[Pipeline] dispatcher thread exiting (frames drained=%u, records=%u)",
           g_statFramesDrained.load(std::memory_order_relaxed),
           g_statRecordsDrained.load(std::memory_order_relaxed));
    return 0;
}

// Append a Record to the current record buffer. CALLER MUST HOLD g_bufferMutex.
// Used inside the locked region of every public Enqueue*.
inline void AppendRecordLocked(const Record& r) {
    g_recordBuffer->records.push_back(r);
    g_statRecordsEnq.fetch_add(1, std::memory_order_relaxed);
}

// Append payload bytes; return offset within the buffer's payload vector.
// CALLER MUST HOLD g_bufferMutex.
inline uint32_t AppendPayloadLocked(const void* data, uint32_t bytes) {
    return g_recordBuffer->AppendPayload(data, bytes);
}

}  // namespace

// =============================================================================
// Public API
// =============================================================================

bool Install() {
    if (g_installed.load(std::memory_order_acquire)) return true;

    g_startEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    g_doneEvent  = CreateEventA(nullptr, FALSE, TRUE,  nullptr);   // initially signaled (no buffer to drain)
    if (!g_startEvent || !g_doneEvent) {
        OD_LOG("[Pipeline] CreateEvent failed: %lu", GetLastError());
        return false;
    }

    g_running.store(true, std::memory_order_release);
    g_dispatchThread = CreateThread(nullptr, 0, DispatchThreadProc, nullptr, 0, nullptr);
    if (!g_dispatchThread) {
        OD_LOG("[Pipeline] CreateThread failed: %lu", GetLastError());
        g_running.store(false, std::memory_order_release);
        return false;
    }
    SetThreadPriority(g_dispatchThread, THREAD_PRIORITY_ABOVE_NORMAL);

    g_installed.store(true, std::memory_order_release);
    g_lastLog = std::chrono::steady_clock::now();
    OD_LOG("[Pipeline] Installed. Dispatcher thread tid=%lu spawned. "
           "Stage 2: DrawPrimitive + DrawIndexedPrimitive deferred to dispatcher.",
           g_dispatchTid);
    return true;
}

bool IsActive() {
    return g_installed.load(std::memory_order_acquire);
}

void Shutdown() {
    if (!g_installed.load(std::memory_order_acquire)) return;
    g_running.store(false, std::memory_order_release);
    SetEvent(g_startEvent);  // wake dispatcher so it sees g_running==false
    if (g_dispatchThread) {
        WaitForSingleObject(g_dispatchThread, 1000);
        CloseHandle(g_dispatchThread);
        g_dispatchThread = nullptr;
    }
    if (g_startEvent) { CloseHandle(g_startEvent); g_startEvent = nullptr; }
    if (g_doneEvent)  { CloseHandle(g_doneEvent);  g_doneEvent  = nullptr; }

    // Shadows are raw-ptr caches now (no refs owned). Just zero them out.
    // Any pending records still hold refs — those will leak if not drained,
    // but DLL unload is ending the process anyway.
    {
        std::lock_guard<std::mutex> lk(g_shadowMutex);
        for (uint32_t i = 0; i < kMaxShadowRenderTargets; ++i) g_shadowRT[i] = nullptr;
        g_shadowDS = nullptr;
        for (uint32_t i = 0; i < kMaxShadowSamplers; ++i) g_shadowTex[i] = nullptr;
        g_shadowVS = nullptr;
        g_shadowPS = nullptr;
        for (uint32_t i = 0; i < kMaxShadowStreams; ++i) g_shadowVB[i] = nullptr;
        g_shadowIB = nullptr;
        g_shadowVDecl = nullptr;
    }

    g_installed.store(false, std::memory_order_release);
}

// -----------------------------------------------------------------------------
// Enqueue functions — record one Op into the active record buffer
// -----------------------------------------------------------------------------

void EnqueueBeginScene() {
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_BeginScene;
    AppendRecordLocked(r);
}

void EnqueueEndScene() {
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_EndScene;
    AppendRecordLocked(r);
}

void EnqueueClear(uint32_t count, const void* rects, uint32_t flags,
                  uint32_t color, float z, uint32_t stencil) {
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_Clear;
    r.args[0] = count;
    r.args[1] = flags;
    r.args[2] = color;
    std::memcpy(&r.args[3], &z, sizeof(float));
    r.args[4] = stencil;
    if (count > 0 && rects) {
        r.payloadOffset = AppendPayloadLocked(rects, count * 16 /* sizeof D3DRECT */);
        r.payloadSize   = count * 16;
    }
    AppendRecordLocked(r);
}

void EnqueueSetTransform(uint32_t state, const void* matrix4x4) {
    if (!matrix4x4) return;
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetTransform;
    r.args[0] = state;
    r.payloadOffset = AppendPayloadLocked(matrix4x4, 64 /* sizeof D3DMATRIX */);
    r.payloadSize   = 64;
    AppendRecordLocked(r);
}

void EnqueueSetViewport(const void* viewport) {
    if (!viewport) return;
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetViewport;
    r.payloadOffset = AppendPayloadLocked(viewport, 24 /* sizeof D3DVIEWPORT9 */);
    r.payloadSize   = 24;
    AppendRecordLocked(r);
}

void EnqueueSetRenderState(uint32_t state, uint32_t value) {
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetRenderState;
    r.args[0] = state;
    r.args[1] = value;
    AppendRecordLocked(r);
}

void EnqueueSetSamplerState(uint32_t sampler, uint32_t type, uint32_t value) {
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetSamplerState;
    r.args[0] = sampler;
    r.args[1] = type;
    r.args[2] = value;
    AppendRecordLocked(r);
}

void EnqueueSetTextureStageState(uint32_t stage, uint32_t type, uint32_t value) {
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetTextureStageState;
    r.args[0] = stage;
    r.args[1] = type;
    r.args[2] = value;
    AppendRecordLocked(r);
}

void EnqueueSetTexture(uint32_t stage, void* texture) {
    auto* t = static_cast<IDirect3DBaseTexture9*>(texture);
    RecordAddRef(t);
    ShadowSetTex(stage, t);
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetTexture;
    r.args[0] = stage;
    r.args[1] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(texture));
    AppendRecordLocked(r);
}

void EnqueueDrawPrimitive(uint32_t primType, uint32_t startVertex, uint32_t primCount) {
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_DrawPrimitive;
    r.args[0] = primType;
    r.args[1] = startVertex;
    r.args[2] = primCount;
    AppendRecordLocked(r);
}

void EnqueueDrawIndexedPrimitive(uint32_t primType, int32_t baseVertexIndex,
                                  uint32_t minVertexIndex, uint32_t numVertices,
                                  uint32_t startIndex, uint32_t primCount) {
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_DrawIndexedPrimitive;
    r.args[0] = primType;
    r.args[1] = static_cast<uint32_t>(baseVertexIndex);
    r.args[2] = minVertexIndex;
    r.args[3] = numVertices;
    r.args[4] = startIndex;
    r.args[5] = primCount;
    AppendRecordLocked(r);
}

void EnqueueSetVertexShader(void* shader) {
    auto* s = static_cast<IDirect3DVertexShader9*>(shader);
    RecordAddRef(s);
    ShadowSetVS(s);
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetVertexShader;
    r.args[0] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(shader));
    AppendRecordLocked(r);
}

void EnqueueSetVertexShaderConstantF(uint32_t startReg, const void* data, uint32_t vec4Count) {
    if (!data || vec4Count == 0) return;
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetVertexShaderConstantF;
    r.args[0] = startReg;
    r.args[1] = vec4Count;
    r.payloadOffset = AppendPayloadLocked(data, vec4Count * 16);
    r.payloadSize   = vec4Count * 16;
    AppendRecordLocked(r);
}

void EnqueueSetPixelShader(void* shader) {
    auto* s = static_cast<IDirect3DPixelShader9*>(shader);
    RecordAddRef(s);
    ShadowSetPS(s);
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetPixelShader;
    r.args[0] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(shader));
    AppendRecordLocked(r);
}

void EnqueueSetPixelShaderConstantF(uint32_t startReg, const void* data, uint32_t vec4Count) {
    if (!data || vec4Count == 0) return;
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetPixelShaderConstantF;
    r.args[0] = startReg;
    r.args[1] = vec4Count;
    r.payloadOffset = AppendPayloadLocked(data, vec4Count * 16);
    r.payloadSize   = vec4Count * 16;
    AppendRecordLocked(r);
}

void EnqueueSetStreamSource(uint32_t streamNum, void* vb, uint32_t offset, uint32_t stride) {
    auto* v = static_cast<IDirect3DVertexBuffer9*>(vb);
    RecordAddRef(v);
    ShadowSetVB(streamNum, v);
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetStreamSource;
    r.args[0] = streamNum;
    r.args[1] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(vb));
    r.args[2] = offset;
    r.args[3] = stride;
    AppendRecordLocked(r);
}

void EnqueueSetStreamSourceFreq(uint32_t streamNum, uint32_t setting) {
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetStreamSourceFreq;
    r.args[0] = streamNum;
    r.args[1] = setting;
    AppendRecordLocked(r);
}

void EnqueueSetIndices(void* ib) {
    auto* i = static_cast<IDirect3DIndexBuffer9*>(ib);
    RecordAddRef(i);
    ShadowSetIB(i);
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetIndices;
    r.args[0] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ib));
    AppendRecordLocked(r);
}

void EnqueueSetVertexDeclaration(void* decl) {
    auto* d = static_cast<IDirect3DVertexDeclaration9*>(decl);
    RecordAddRef(d);
    ShadowSetVDecl(d);
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetVertexDeclaration;
    r.args[0] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(decl));
    AppendRecordLocked(r);
}

void EnqueueSetRenderTarget(uint32_t index, void* surface) {
    auto* s = static_cast<IDirect3DSurface9*>(surface);
    RecordAddRef(s);                  // buffer record AddRef (Released by DoReplay)
    ShadowSetRT(index, s);            // raw-ptr cache for Mirror_GetRT
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetRenderTarget;
    r.args[0] = index;
    r.args[1] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(surface));
    AppendRecordLocked(r);
}

// Compute vertex count from D3DPRIMITIVETYPE + primitive count. Mirrors the
// MSDN table.
static inline uint32_t VertexCountFromPrim(uint32_t primType, uint32_t primCount) {
    switch (primType) {
        case 1 /*D3DPT_POINTLIST*/:    return primCount;
        case 2 /*D3DPT_LINELIST*/:     return primCount * 2;
        case 3 /*D3DPT_LINESTRIP*/:    return primCount + 1;
        case 4 /*D3DPT_TRIANGLELIST*/: return primCount * 3;
        case 5 /*D3DPT_TRIANGLESTRIP*/:
        case 6 /*D3DPT_TRIANGLEFAN*/:  return primCount + 2;
        default: return 0;
    }
}

void EnqueueDrawPrimitiveUP(uint32_t primType, uint32_t primCount,
                             const void* vertexData, uint32_t stride) {
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_DrawPrimitiveUP;
    r.args[0] = primType;
    r.args[1] = primCount;
    r.args[2] = stride;
    if (vertexData && stride > 0 && primCount > 0) {
        const uint32_t vertexCount = VertexCountFromPrim(primType, primCount);
        const uint32_t dataBytes   = vertexCount * stride;
        if (dataBytes > 0) {
            r.payloadOffset = AppendPayloadLocked(vertexData, dataBytes);
            r.payloadSize   = dataBytes;
        }
    }
    AppendRecordLocked(r);
}

void EnqueueSetFVF(uint32_t fvf) {
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetFVF;
    r.args[0] = fvf;
    AppendRecordLocked(r);
}

void EnqueueSetDepthStencilSurface(void* surface) {
    auto* s = static_cast<IDirect3DSurface9*>(surface);
    RecordAddRef(s);
    ShadowSetDS(s);
    std::lock_guard<std::mutex> lk(g_bufferMutex);
    Record r{};
    r.op = overdrive::replay::REP_SetDepthStencilSurface;
    r.args[0] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(surface));
    AppendRecordLocked(r);
}

// Shadow getters — return RAW pointer (no AddRef). Caller AddRef's if it
// needs an owning ref. Pointer is alive because either the buffer record
// holds an AddRef (latest queued Set) or D3D9's internal device-state ref
// holds it (after dispatch). Returns nullptr if no Set has been issued.
void* GetShadowRenderTarget(uint32_t index) {
    if (index >= kMaxShadowRenderTargets) return nullptr;
    std::lock_guard<std::mutex> lk(g_shadowMutex);
    return g_shadowRT[index];
}

void* GetShadowDepthStencilSurface() {
    std::lock_guard<std::mutex> lk(g_shadowMutex);
    return g_shadowDS;
}

// -----------------------------------------------------------------------------
// Present-boundary handler — swap buffers and signal the dispatcher
// -----------------------------------------------------------------------------

void OnPresentBoundary(IDirect3DDevice9* /*dev*/) {
    if (!g_installed.load(std::memory_order_acquire)) return;

    // Wait for the dispatcher to finish the *previous* frame's buffer.
    // Without this we'd swap into a buffer the dispatcher is still reading.
    // Fast-path: g_doneEvent is auto-reset and starts signaled, so on the
    // first call there's no real wait. Wait OUTSIDE the buffer mutex so other
    // threads can keep enqueuing.
    DWORD waitResult = WaitForSingleObject(g_doneEvent, 0);
    if (waitResult == WAIT_TIMEOUT) {
        g_statBufferSwapWaits.fetch_add(1, std::memory_order_relaxed);
        WaitForSingleObject(g_doneEvent, INFINITE);
    }

    // Swap pointers under the buffer mutex so any in-flight Enqueue* on a
    // peer thread completes its push before we hand the buffer to the
    // dispatcher.
    {
        std::lock_guard<std::mutex> lk(g_bufferMutex);
        Buffer* tmp = g_recordBuffer;
        g_recordBuffer   = g_dispatchBuffer;
        g_dispatchBuffer = tmp;
    }

    g_statFramesEnqueued.fetch_add(1, std::memory_order_relaxed);

    // Signal the dispatcher that the new dispatchBuffer is ready.
    SetEvent(g_startEvent);
}

// -----------------------------------------------------------------------------
// Flush — block until the dispatcher catches up
// -----------------------------------------------------------------------------

void Flush() {
    if (!g_installed.load(std::memory_order_acquire)) return;
    g_statFlushes.fetch_add(1, std::memory_order_relaxed);

    // 1. Wait for any previous dispatch to finish (so we can swap safely).
    //    Done OUTSIDE g_bufferMutex so other Skyrim threads can keep enqueuing
    //    (those records will dispatch on the NEXT Flush, not this one).
    WaitForSingleObject(g_doneEvent, INFINITE);

    // 2. Atomically swap record↔dispatch pointers. With the lock held, no
    //    Enqueue* can be mid-push. After the swap, peer threads' new
    //    Enqueue*s land in the now-empty record buffer; this Flush takes
    //    only what was already queued.
    {
        std::lock_guard<std::mutex> lk(g_bufferMutex);
        Buffer* tmp = g_recordBuffer;
        g_recordBuffer   = g_dispatchBuffer;
        g_dispatchBuffer = tmp;
    }

    // 3. Hand the swapped buffer to the dispatcher.
    SetEvent(g_startEvent);

    // 4. Wait for it to drain — DO NOT hold g_bufferMutex; peer enqueues
    //    must remain unblocked.
    WaitForSingleObject(g_doneEvent, INFINITE);

    // 5. Re-signal so subsequent waiters see "no dispatch in flight".
    //    Auto-reset events stay un-signaled after one wait.
    SetEvent(g_doneEvent);
}

// -----------------------------------------------------------------------------
// Stats
// -----------------------------------------------------------------------------

Stats GetStats() {
    Stats s;
    s.framesEnqueued       = g_statFramesEnqueued.load(std::memory_order_relaxed);
    s.framesDrained        = g_statFramesDrained.load(std::memory_order_relaxed);
    s.recordsEnqueuedTotal = g_statRecordsEnq.load(std::memory_order_relaxed);
    s.recordsDrainedTotal  = g_statRecordsDrained.load(std::memory_order_relaxed);
    s.flushes              = g_statFlushes.load(std::memory_order_relaxed);
    s.bufferSwapWaits      = g_statBufferSwapWaits.load(std::memory_order_relaxed);
    return s;
}

void MaybeLogStats() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog);
    if (elapsed.count() < 5000) return;
    g_lastLog = now;
    if (!g_installed.load(std::memory_order_acquire)) return;

    const Stats s = GetStats();
    OD_LOG("[Pipeline] frames=%u/%u (enq/drain) records=%u/%u flushes=%u "
           "swapWaits=%u dispatcherTid=%lu",
           s.framesEnqueued, s.framesDrained,
           s.recordsEnqueuedTotal, s.recordsDrainedTotal,
           s.flushes, s.bufferSwapWaits, g_dispatchTid);
}

}
