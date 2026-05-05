#pragma once

#include <cstdint>

struct IDirect3DDevice9;

namespace overdrive::pipeline {

// =============================================================================
// D3D9 pipeline dispatcher — multi-core rendering scaffolding
// =============================================================================
//
// Goal: split the rendering work across two threads.
//
//   T_record   = Skyrim's render thread (T5728 in the per-thread profile).
//                Runs Skyrim's scenegraph code + our Mirror_* wrappers.
//                Mirror_* dispatches to ENQUEUE (record into a per-frame
//                buffer) instead of calling D3D9 directly.
//
//   T_dispatch = our worker thread. Drains the previous frame's buffer by
//                calling orig<>() against the real D3D9 device. Holds the
//                D3D9 driver lock; T_record never blocks on the driver.
//
// During steady-state operation:
//
//   Frame N+1 on T_record:                    Frame N on T_dispatch:
//   ----------------------                    -----------------------
//   ... scenegraph traversal ...              ... orig<DrawPrimitive>() ...
//   Mirror_DrawIndexedPrimitive ─enqueue→     ... orig<SetTexture>() ...
//   Mirror_SetRenderState     ─enqueue→       ... orig<SetVertexShader>() ...
//   ...                                       ... orig<Present>() ...
//
// Both cores active concurrently. Pipeline depth = 1 frame.
//
// =============================================================================
// Synchronization model
// =============================================================================
//
// Two ping-pong buffers (A, B). At any moment one is the *record* buffer
// (writable by T_record) and one is the *dispatch* buffer (readable by
// T_dispatch). At frame boundary (Present), T_record:
//   1. Records the Present op into the current record buffer.
//   2. Waits for T_dispatch to finish the previous frame's buffer (so we
//      don't overwrite it).
//   3. Swaps the pointers — record buffer becomes dispatch buffer; the
//      drained buffer becomes the new (empty) record buffer.
//   4. Signals T_dispatch to start draining the new dispatch buffer.
//   5. Returns to caller; next frame's recording begins immediately.
//
// =============================================================================
// Coherence rules (invariants the dispatcher enforces)
// =============================================================================
//
// 1. Set* methods are deferred: T_record records, returns D3D_OK without
//    forwarding. T_dispatch later forwards in submission order.
// 2. Get* methods are NOT in our typed-wrapper set, so they pass through
//    counter thunks straight to D3D9 — but they read REAL device state,
//    which lags the recorded state by 1 frame. Callers must call Flush()
//    before any Get* if they need to see their own preceding Set*.
// 3. Create* methods (resource creation) are not deferred. They forward
//    immediately so the caller gets the real resource pointer back.
// 4. Present is the only built-in flush point: T_record's "swap+signal"
//    at Present implicitly drains the previous frame.
//
// =============================================================================
// Lifecycle
// =============================================================================
//
//   Install()  — spawn T_dispatch, allocate buffers. Call from BootstrapThread.
//   Enqueue*() — called from Mirror_* on T_record. Records into the active
//                record buffer.
//   Flush()    — block T_record until T_dispatch has caught up. Used at
//                Get* call sites and on shutdown.
//   Shutdown() — drain remaining work, join T_dispatch, free buffers.

// Spawn T_dispatch and allocate the ping-pong buffers. Idempotent.
// Returns false if the thread couldn't be created.
bool Install();

// Drain remaining records, join the dispatcher thread.
void Shutdown();

// Returns true if Install() succeeded and the dispatcher is running.
// Mirror_* uses this to decide whether to enqueue (deferred) or call
// orig<>() directly (synchronous fallback).
bool IsActive();

// =============================================================================
// State shadow — what RT/DS are CURRENTLY queued (the right value to return
// from Get*, since real device state lags by however much the dispatcher has
// not yet drained).
// =============================================================================
//
// Solves two problems simultaneously:
//
// 1. Get* coherence. Skyrim functions like the one at 0x00F874C0 do
//    `GetRenderTarget(0, &saved); saved->GetDesc(&desc); ...`. With deferred
//    SetRenderTarget the real device returns the OLD RT, the function reads
//    the OLD RT's description, and downstream sizing/format decisions are
//    wrong → visual glitches.
//
// 2. Resource lifetime. Without a shadow, a deferred SetRenderTarget(surf)
//    queues `surf` in the buffer. Real D3D9 hasn't AddRef'd `surf` yet. If
//    the app immediately `surf->Release()` (which is legal because GetRT
//    returned an AddRef'd ptr that the caller is supposed to release), surf's
//    refcount drops to 0 and it's destroyed before the dispatcher's
//    orig<SetRT>(surf) runs — dangling-pointer dispatch.
//
// Shadow semantics:
//   - On EnqueueSetRenderTarget(idx, newSurf): AddRef newSurf, Release the
//     previous shadow at that index, store newSurf in shadow.
//   - On Mirror_GetRenderTarget(idx, &out): read shadow, AddRef the result,
//     write into *out, return D3D_OK. The caller's eventual Release() pairs
//     with the AddRef we just did.
//   - On Pipeline::Shutdown: Release all shadow entries.
//
// The shadow is the AUTHORITATIVE current-RT for the queued state. Real
// D3D9's RT lags behind the shadow by whatever's still in the dispatch
// buffer; the dispatcher catches up at Flush.

constexpr uint32_t kMaxShadowRenderTargets = 4;

// Look up the shadow render target for a given index. Returns the surface
// pointer with one AddRef applied (caller must Release). Returns nullptr if
// no Set has been issued for that index yet. Type is `IDirect3DSurface9*`
// but exposed as void* to keep the header free of d3d9.h.
void* GetShadowRenderTarget(uint32_t index);
void* GetShadowDepthStencilSurface();

// =============================================================================
// Enqueue API — called from Mirror_* on the render thread
// =============================================================================
//
// Each function records one D3D9 op into the active record buffer. They map
// 1:1 onto overdrive::replay::Op enum entries; the dispatcher uses the
// existing DoReplay switch in D3D9Mirror.cpp to dispatch them through orig<>.

void EnqueueBeginScene();
void EnqueueEndScene();
void EnqueueClear(uint32_t count, const void* rects, uint32_t flags,
                  uint32_t color, float z, uint32_t stencil);
void EnqueueSetTransform(uint32_t state, const void* matrix4x4);
void EnqueueSetViewport(const void* viewport);
void EnqueueSetRenderState(uint32_t state, uint32_t value);
void EnqueueSetSamplerState(uint32_t sampler, uint32_t type, uint32_t value);
void EnqueueSetTextureStageState(uint32_t stage, uint32_t type, uint32_t value);
void EnqueueSetTexture(uint32_t stage, void* texture);
void EnqueueDrawPrimitive(uint32_t primType, uint32_t startVertex, uint32_t primCount);
void EnqueueDrawIndexedPrimitive(uint32_t primType, int32_t baseVertexIndex,
                                  uint32_t minVertexIndex, uint32_t numVertices,
                                  uint32_t startIndex, uint32_t primCount);
void EnqueueSetVertexShader(void* shader);
void EnqueueSetVertexShaderConstantF(uint32_t startReg, const void* data, uint32_t vec4Count);
void EnqueueSetPixelShader(void* shader);
void EnqueueSetPixelShaderConstantF(uint32_t startReg, const void* data, uint32_t vec4Count);
void EnqueueSetStreamSource(uint32_t streamNum, void* vb, uint32_t offset, uint32_t stride);
void EnqueueSetStreamSourceFreq(uint32_t streamNum, uint32_t setting);
void EnqueueSetIndices(void* ib);
void EnqueueSetVertexDeclaration(void* decl);
void EnqueueSetRenderTarget(uint32_t index, void* surface);
void EnqueueSetDepthStencilSurface(void* surface);

// DrawPrimitiveUP — vertex data is user-supplied transient memory; we MUST
// copy it into the buffer payload before the dispatcher consumes it (the
// app may overwrite/free the buffer the moment the call returns).
void EnqueueDrawPrimitiveUP(uint32_t primType, uint32_t primCount,
                             const void* vertexData, uint32_t stride);

// SetFVF — trivial DWORD value, no resource refs.
void EnqueueSetFVF(uint32_t fvf);

// Frame-boundary handler. Called from the Present hook on T_record:
//   1. Records a Present op into the current record buffer.
//   2. Waits for T_dispatch to finish the previous dispatch buffer.
//   3. Swaps record↔dispatch and signals T_dispatch to start.
//   4. Returns; T_record proceeds with frame N+1's recording.
void OnPresentBoundary(IDirect3DDevice9* dev);

// Block T_record until T_dispatch has processed all currently-recorded ops.
// Use before any Get* that needs to observe preceding Set*. Cost: full
// pipeline drain + serial dispatch.
void Flush();

// =============================================================================
// Stats (periodic log line)
// =============================================================================

struct Stats {
    uint32_t framesEnqueued;
    uint32_t framesDrained;
    uint32_t recordsEnqueuedTotal;
    uint32_t recordsDrainedTotal;
    uint32_t flushes;             // explicit Flush() calls
    uint32_t bufferSwapWaits;     // times T_record blocked at Present
};
Stats GetStats();

void MaybeLogStats();

}
