#pragma once
#include <cstdint>
#include <vector>
#include <d3d9.h>

// =============================================================================
// D3D9 deferred replay buffer — Week 1 of the multi-core drawcall plan
// =============================================================================
//
// Each thread has its own recording state. When `g_recording` is true, the
// `Mirror_*` typed wrappers in D3D9Mirror.cpp push a Record into this thread's
// Buffer instead of calling the real D3D9 function. After recording, a single
// thread calls Replay() to issue the orig<> D3D9 calls in the original order.
//
// The recording mode skips D3D9 calls — if the caller doesn't subsequently
// Replay() the buffer, GPU state is wrong. The whole-stream contract is
// "StartRecording → run scope → StopRecording → Replay (or discard)".
//
// Resource-creating methods (CreateTexture, CreateVertexBuffer, etc.) are NOT
// deferred even in recording mode: they return new resource pointers that the
// caller uses immediately. Those wrappers always pass through to D3D9.

namespace overdrive::replay {

enum Op : uint16_t {
    REP_NONE = 0,
    REP_BeginScene,
    REP_EndScene,
    REP_Clear,
    REP_SetTransform,
    REP_SetViewport,
    REP_SetRenderState,
    REP_SetSamplerState,
    REP_SetTextureStageState,
    REP_SetTexture,
    REP_DrawPrimitive,
    REP_DrawIndexedPrimitive,
    REP_SetVertexShader,
    REP_SetVertexShaderConstantF,
    REP_SetPixelShader,
    REP_SetPixelShaderConstantF,
    REP_SetStreamSource,
    REP_SetStreamSourceFreq,
    REP_SetIndices,
    REP_SetVertexDeclaration,
    REP_SetRenderTarget,
    REP_SetDepthStencilSurface,
    REP_DrawPrimitiveUP,
    REP_SetFVF,
    REP_COUNT_,
};

// 36-byte record. Args fit DrawIndexedPrimitive (the widest plain-args op):
//   D3DPRIMITIVETYPE Type, INT BaseVertexIndex, UINT MinVertexIndex,
//   UINT NumVertices, UINT startIndex, UINT primCount  →  6 × uint32_t.
// Variable-size data (matrix, viewport, constant arrays, clear rects) lives
// in `Buffer::payload` referenced via offset+size.
struct Record {
    uint16_t op;
    uint16_t pad0;
    uint32_t args[6];
    uint32_t payloadOffset;
    uint32_t payloadSize;
};
static_assert(sizeof(Record) == 36, "Record layout drift");

struct Buffer {
    std::vector<Record>  records;
    std::vector<uint8_t> payload;

    void Clear() { records.clear(); payload.clear(); }

    // Append payload bytes (e.g. a D3DMATRIX or constant array); return its
    // offset within `payload`. The caller stores that offset + size in the
    // Record so Replay() can find it.
    //
    // Implementation: resize + memcpy, NOT vector::insert(iter, p, p+bytes).
    // Profiling on 2026-05-05 showed iterator-construction overhead (visible
    // as `std::_Iterator_base12::_Iterator_base12` and `vector::data` at
    // ~5.7% of render-thread CPU combined). resize() value-inits to zero
    // for uint8_t which the compiler lowers to memset; the subsequent memcpy
    // then overwrites those bytes. Both ops are tight loops with no iterator
    // wrapping. Net is faster on this hot path despite the redundant memset.
    uint32_t AppendPayload(const void* data, uint32_t bytes) {
        const uint32_t off = static_cast<uint32_t>(payload.size());
        payload.resize(off + bytes);
        std::memcpy(payload.data() + off, data, bytes);
        return off;
    }
};

// Per-thread recording state. Defined in D3D9Replay.cpp.
extern thread_local bool   g_recording;
extern thread_local Buffer g_buffer;

inline bool   IsRecording()    { return g_recording; }
inline Buffer& CurrentBuffer() { return g_buffer; }

void StartRecording();
void StopRecording();

// Replay this thread's buffer through real D3D9 (calls the orig<> trampolines).
// Implementation lives in D3D9Mirror.cpp's anonymous namespace (where orig<> is
// reachable) and is registered here via SetReplayImpl at static-init time.
// Caller must NOT be in recording mode (we're issuing real D3D9 calls).
HRESULT Replay(IDirect3DDevice9* dev, const Buffer& buf);

// Used by D3D9Mirror.cpp's static initializer to register the dispatch impl.
// Idempotent: last set wins (but in practice it's set exactly once).
using ReplayFn = HRESULT (*)(IDirect3DDevice9*, const Buffer&);
void SetReplayImpl(ReplayFn fn);

// Cumulative stats — across all threads since DLL load. Used by the periodic
// log to report recording / replay activity.
//
// 32-bit (not 64-bit) on purpose. On x86-32, std::atomic<uint64_t>::fetch_add
// compiles to a LOCK CMPXCHG8B loop (~50 cycles); atomic<uint32_t>::fetch_add
// is a single LOCK XADD (~10 cycles). Profiling on 2026-05-03 (Week 2 deploy)
// showed the uint64 fetch_add at 3.45% of render-thread CPU. Per-second deltas
// remain wrap-safe under unsigned subtraction.
uint32_t StatsRecorded();
uint32_t StatsReplayed();
// Implementation hook used by Replay() in D3D9Mirror.cpp to bump the global
// replayed-count atomic without exposing it directly.
void NoteReplayedCount(uint32_t n);

// Captured D3D9 device. Set once by mirror::Install(dev). Used by the
// hot-sub thunks (NiDX9Hooks.cpp) to know which device to Replay() against.
void              SetDevice(IDirect3DDevice9* dev);
IDirect3DDevice9* GetDevice();

}
