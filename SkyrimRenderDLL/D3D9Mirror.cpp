#include "D3D9Mirror.h"
#include "D3D9DeviceVtable.h"
#include "DebugLogger.h"
#include "VulkanCommandQueue.h"
#include "ResourceMirror.h"
#include "D3D9Replay.h"
#include "D3D9PipelineDispatcher.h"
#include "D3D9ReadProfiler.h"

#include <intrin.h>  // _ReturnAddress()

#include <windows.h>
#include <d3d9.h>
#include <chrono>

namespace overdrive::mirror {

Stats           gStats;
ResourceTotals  gResources;

namespace {

// IDirect3DDevice9 vtable indices we install typed wrappers for. Mirror these
// against d3d9vt::kSlotNames in D3D9DeviceVtable.cpp if you change the order.
constexpr int kSlot_BeginScene             = 41;
constexpr int kSlot_EndScene               = 42;
constexpr int kSlot_Clear                  = 43;
constexpr int kSlot_SetTransform           = 44;
constexpr int kSlot_SetViewport            = 47;
constexpr int kSlot_SetRenderState         = 57;
constexpr int kSlot_SetTextureStageState   = 67;
constexpr int kSlot_SetSamplerState        = 69;
constexpr int kSlot_SetTexture             = 65;
constexpr int kSlot_DrawPrimitive          = 81;
constexpr int kSlot_DrawIndexedPrimitive   = 82;
constexpr int kSlot_SetVertexShader        = 92;
constexpr int kSlot_SetVertexShaderConstantF = 94;
constexpr int kSlot_SetPixelShader         = 107;
constexpr int kSlot_SetPixelShaderConstantF= 109;
constexpr int kSlot_SetStreamSource        = 100;
constexpr int kSlot_SetStreamSourceFreq    = 102;
constexpr int kSlot_SetIndices             = 104;
constexpr int kSlot_SetVertexDeclaration   = 87;
constexpr int kSlot_CreateTexture          = 23;
constexpr int kSlot_CreateVertexBuffer     = 26;
constexpr int kSlot_CreateIndexBuffer      = 27;
constexpr int kSlot_CreateVertexShader     = 91;
constexpr int kSlot_CreatePixelShader      = 106;
constexpr int kSlot_SetRenderTarget        = 37;
constexpr int kSlot_SetDepthStencilSurface = 39;

// Get* slots — wrapped only to capture the calling TESV.exe retaddr (via the
// _ReturnAddress() intrinsic). The wrapper passes through to orig<>() with
// no logic change, so behavior is unaffected. The captured retaddrs are
// bucketed by readprofiler:: and dumped periodically with TESV symbol
// resolution. This is the runtime debugger for "where does Skyrim read D3D9
// state from" — those call sites are the most likely glitch sources under
// the deferred-Set* pipeline.
constexpr int kSlot_GetRenderTarget          = 38;
constexpr int kSlot_GetDepthStencilSurface   = 40;
constexpr int kSlot_GetTransform             = 45;
constexpr int kSlot_GetViewport              = 48;
constexpr int kSlot_GetRenderState           = 58;
constexpr int kSlot_GetTexture               = 64;
constexpr int kSlot_GetTextureStageState     = 66;
constexpr int kSlot_GetSamplerState          = 68;
constexpr int kSlot_GetVertexDeclaration     = 88;
constexpr int kSlot_GetVertexShader          = 93;
constexpr int kSlot_GetVertexShaderConstantF = 95;
constexpr int kSlot_GetStreamSource          = 101;
constexpr int kSlot_GetIndices               = 105;
constexpr int kSlot_GetPixelShader           = 108;
constexpr int kSlot_GetPixelShaderConstantF  = 110;

// Stage 6 — UI/HUD ops that previously bypassed the pipeline (sync on T_record).
// `[D3D9VT]` showed DrawPrimitiveUP + SetFVF firing 1:1 at ~60/s during gameplay
// — they're paired (SetFVF then DrawPrimitiveUP). Running sync while the pipeline
// has queued state means the UI draws hit real D3D9 with whatever state was
// last applied by the dispatcher, not what Skyrim intended. Deferring them
// closes that ordering gap.
constexpr int kSlot_DrawPrimitiveUP          = 83;
constexpr int kSlot_SetFVF                   = 89;

// ============================================================================
// State cache for redundant-call elimination
// ============================================================================
//
// D3D9 driver state is sticky — calling SetSamplerState(s, t, v) when the
// current value at (s, t) is already v is a no-op visually, but still costs:
//   - virtual call dispatch (vtable lookup, hooked further by ENB)
//   - driver thunk + parameter validation
//   - state-block bookkeeping
//   - eventual GPU-visible command (sometimes)
//
// In Skyrim's case the log shows ~238k SetSamplerState calls/sec — the
// majority are setting the value already in effect. Caching last-set value
// per slot and skipping redundant calls is one of the highest-ROI perf
// optimizations available without replacing D3D9.

// Capacities chosen large enough for D3D9 spec maxima.
constexpr int kMaxSamplerSlots             = 16;
constexpr int kMaxSamplerStateTypes        = 32;   // D3DSAMP_* enum max ~13
constexpr int kMaxTextureStages            = 8;
constexpr int kMaxTextureStageStateTypes   = 64;   // D3DTSS_* enum max ~33
constexpr int kMaxRenderStateTypes         = 256;  // D3DRS_* enum sparse to ~209

// Stream binding slots: 16 is the D3D9 max; D3DCAPS9::MaxStreams confirms.
constexpr int kMaxStreams                  = 16;
// Transform state index range: D3DTS_WORLDMATRIX(255) = 256+255 = 511.
constexpr int kMaxTransformStates          = 512;
// Shader constant register counts (sm_3.0 max).
constexpr int kMaxVSConstantRegisters      = 256;
constexpr int kMaxPSConstantRegisters      = 224;

struct StreamBinding {
    IDirect3DVertexBuffer9* vb = nullptr;
    UINT                    offset = 0;
    UINT                    stride = 0;
};

struct StateCache {
    DWORD samplerState[kMaxSamplerSlots][kMaxSamplerStateTypes]            = {};
    bool  samplerStateSet[kMaxSamplerSlots][kMaxSamplerStateTypes]          = {};

    DWORD tssState[kMaxTextureStages][kMaxTextureStageStateTypes]          = {};
    bool  tssStateSet[kMaxTextureStages][kMaxTextureStageStateTypes]        = {};

    DWORD renderState[kMaxRenderStateTypes]                                 = {};
    bool  renderStateSet[kMaxRenderStateTypes]                              = {};

    IDirect3DBaseTexture9*    boundTexture[kMaxSamplerSlots]                = {};
    bool                      boundTextureSet[kMaxSamplerSlots]             = {};

    IDirect3DVertexShader9*   boundVertexShader                             = nullptr;
    bool                      boundVertexShaderSet                          = false;

    IDirect3DPixelShader9*    boundPixelShader                              = nullptr;
    bool                      boundPixelShaderSet                           = false;

    // Stream source bindings — (buffer ptr, offset, stride) per stream slot.
    StreamBinding             stream[kMaxStreams]                           = {};
    bool                      streamSet[kMaxStreams]                        = {};

    // SetStreamSourceFreq: per-stream divider/instance-count flag word.
    UINT                      streamFreq[kMaxStreams]                       = {};
    bool                      streamFreqSet[kMaxStreams]                    = {};

    // Single index buffer pointer.
    IDirect3DIndexBuffer9*    boundIndices                                  = nullptr;
    bool                      boundIndicesSet                               = false;

    // Single vertex declaration.
    void*                     boundVertexDecl                               = nullptr;
    bool                      boundVertexDeclSet                            = false;

    // Fixed-function transform matrices, indexed by D3DTRANSFORMSTATETYPE.
    // Each entry is 64 bytes; 512 * 64 = 32 KB total.
    float                     transform[kMaxTransformStates][16]            = {};
    bool                      transformSet[kMaxTransformStates]             = {};

    // Viewport: 24-byte struct.
    D3DVIEWPORT9              viewport                                      = {};
    bool                      viewportSet                                   = false;

    // Shader constants: per-register float4 cache. memcmp 16 bytes per check.
    float                     vsConstantF[kMaxVSConstantRegisters][4]       = {};
    bool                      vsConstantFSet[kMaxVSConstantRegisters]       = {};
    float                     psConstantF[kMaxPSConstantRegisters][4]       = {};
    bool                      psConstantFSet[kMaxPSConstantRegisters]       = {};
};
StateCache g_cache;

// Master switch for the dedup. If a regression appears, flip to false and
// recompile — every dedupable wrapper falls back to "always call original".
constexpr bool kDedupEnabled = true;

// ============================================================================
// Per-category dedup toggles
// ============================================================================
//
// User reported water texture glitches with all categories enabled. Disable
// the most likely culprits by default while keeping the safe high-yield ones.
//
// Suspected risk model:
//   - Shader binding dedup: D3D9 can recycle pointer addresses when a shader
//     is released and re-created. If our cached pointer aliases, we skip a
//     real shader change.
//   - Shader constant dedup: water uses time-varying ripple constants. Edge
//     cases (ENB writing constants in parallel, identical bit patterns from
//     unrelated objects, register-meaning shifts across shader changes) can
//     desync the shader's expected inputs.
//   - Texture binding: ENB rebinds textures aggressively for postFX; risk of
//     desync if cache doesn't match driver state.
//
// Flip any of these to true individually to isolate which category causes
// each visual artifact.
constexpr bool kDedup_SamplerState         = true;    // 90% skip rate; safe
constexpr bool kDedup_TextureStageState    = true;    // 100% skip; legacy fixed-func
constexpr bool kDedup_RenderState          = true;    // 81% skip; safe
constexpr bool kDedup_Texture              = false;   // 37% skip but ENB rebinds — risky
constexpr bool kDedup_VertexShader         = false;   // pointer-aliasing risk
constexpr bool kDedup_PixelShader          = false;   // pointer-aliasing risk
constexpr bool kDedup_StreamSource         = true;    // 10% skip; safe
constexpr bool kDedup_StreamSourceFreq     = true;    // 52% skip; safe
constexpr bool kDedup_Indices              = true;    // 14% skip; safe
constexpr bool kDedup_VertexDeclaration    = true;    // <1% skip; safe
constexpr bool kDedup_Transform            = true;    // 47% skip; safe
constexpr bool kDedup_Viewport             = true;    // 63% skip; safe
constexpr bool kDedup_VSConstantF          = false;   // SUSPECTED water culprit
constexpr bool kDedup_PSConstantF          = false;   // SUSPECTED water culprit

// Function-pointer typedefs matching the IDirect3DDevice9 vtable. STDMETHODCALLTYPE
// (= __stdcall on x86) — caller pushes args, callee cleans up.
using PFN_BeginScene             = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*);
using PFN_EndScene               = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*);
using PFN_Clear                  = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, DWORD, const D3DRECT*, DWORD, D3DCOLOR, float, DWORD);
using PFN_SetTransform           = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, D3DTRANSFORMSTATETYPE, const D3DMATRIX*);
using PFN_SetViewport            = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, const D3DVIEWPORT9*);
using PFN_SetRenderState         = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, D3DRENDERSTATETYPE, DWORD);
using PFN_SetSamplerState        = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, DWORD, D3DSAMPLERSTATETYPE, DWORD);
using PFN_SetTextureStageState   = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, DWORD, D3DTEXTURESTAGESTATETYPE, DWORD);
using PFN_SetTexture             = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, DWORD, IDirect3DBaseTexture9*);
using PFN_DrawPrimitive          = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, D3DPRIMITIVETYPE, UINT, UINT);
using PFN_DrawIndexedPrimitive   = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, D3DPRIMITIVETYPE, INT, UINT, UINT, UINT, UINT);
using PFN_SetVertexShader        = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, IDirect3DVertexShader9*);
using PFN_SetVertexShaderConstantF = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, UINT, const float*, UINT);
using PFN_SetPixelShader         = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, IDirect3DPixelShader9*);
using PFN_SetPixelShaderConstantF= HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, UINT, const float*, UINT);
using PFN_SetStreamSource        = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, UINT, IDirect3DVertexBuffer9*, UINT, UINT);
using PFN_SetStreamSourceFreq    = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, UINT, UINT);
using PFN_SetIndices             = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, IDirect3DIndexBuffer9*);
using PFN_SetVertexDeclaration   = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, IDirect3DVertexDeclaration9*);
using PFN_CreateTexture          = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, UINT, UINT, UINT, DWORD, D3DFORMAT, D3DPOOL, IDirect3DTexture9**, HANDLE*);
using PFN_CreateVertexBuffer     = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, UINT, DWORD, DWORD, D3DPOOL, IDirect3DVertexBuffer9**, HANDLE*);
using PFN_CreateIndexBuffer      = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, UINT, DWORD, D3DFORMAT, D3DPOOL, IDirect3DIndexBuffer9**, HANDLE*);
using PFN_CreateVertexShader     = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, const DWORD*, IDirect3DVertexShader9**);
using PFN_CreatePixelShader      = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, const DWORD*, IDirect3DPixelShader9**);
using PFN_SetRenderTarget        = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, DWORD, IDirect3DSurface9*);
using PFN_SetDepthStencilSurface = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, IDirect3DSurface9*);

// PFN typedefs for Get* methods (read-only; just for retaddr profiling).
using PFN_GetRenderTarget          = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, DWORD, IDirect3DSurface9**);
using PFN_GetDepthStencilSurface   = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, IDirect3DSurface9**);
using PFN_GetTransform             = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, D3DTRANSFORMSTATETYPE, D3DMATRIX*);
using PFN_GetViewport              = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, D3DVIEWPORT9*);
using PFN_GetRenderState           = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, D3DRENDERSTATETYPE, DWORD*);
using PFN_GetTexture               = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, DWORD, IDirect3DBaseTexture9**);
using PFN_GetTextureStageState     = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, DWORD, D3DTEXTURESTAGESTATETYPE, DWORD*);
using PFN_GetSamplerState          = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, DWORD, D3DSAMPLERSTATETYPE, DWORD*);
using PFN_GetVertexDeclaration     = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, IDirect3DVertexDeclaration9**);
using PFN_GetVertexShader          = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, IDirect3DVertexShader9**);
using PFN_GetVertexShaderConstantF = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, UINT, float*, UINT);
using PFN_GetStreamSource          = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, UINT, IDirect3DVertexBuffer9**, UINT*, UINT*);
using PFN_GetIndices               = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, IDirect3DIndexBuffer9**);
using PFN_GetPixelShader           = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, IDirect3DPixelShader9**);
using PFN_GetPixelShaderConstantF  = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, UINT, float*, UINT);
using PFN_DrawPrimitiveUP          = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, D3DPRIMITIVETYPE, UINT, const void*, UINT);
using PFN_SetFVF                   = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*, DWORD);

// Helper: chain to original. The bulk-hook stored every vtable slot's pre-hook
// function pointer in d3d9vt::gOriginals[]. We cast to the right typedef.
template <typename PFN, int Slot>
inline PFN orig() {
    return reinterpret_cast<PFN>(d3d9vt::gOriginals[Slot]);
}

// -------- Typed wrappers --------
//
// Each wrapper:
//   1. Increments the corresponding Stats counter (Vulkan-side mirror state)
//   2. Calls the original D3D9 method (so the game still renders correctly)
//   3. Returns the original's result
//
// This is "observe + chain". Future phases will replace step 2 with actual
// Vulkan command emission.

// NOTE on recording-mode placement: the `if (replay::IsRecording())` branch sits
// AFTER dedup logic and AFTER vkq mirror push, but BEFORE the orig<>() call.
// This means:
//   - Dedup-skipped calls don't enter the buffer (they're genuine no-ops)
//   - vkq mirror state stays coherent regardless of recording mode
//   - The buffer holds only the calls that would have been forwarded to D3D9
// Then on Replay, orig<>() is called for each buffered survivor.

extern "C" HRESULT STDMETHODCALLTYPE Mirror_BeginScene(IDirect3DDevice9* This) {
    gStats.beginScene.fetch_add(1, std::memory_order_relaxed);
    vkq::PushOp1(vkq::CMD_BEGIN_SCENE, 0);
    if (replay::IsRecording()) {
        replay::Record r{};
        r.op = replay::REP_BeginScene;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) { pipeline::EnqueueBeginScene(); return D3D_OK; }
    return orig<PFN_BeginScene, kSlot_BeginScene>()(This);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_EndScene(IDirect3DDevice9* This) {
    gStats.endScene.fetch_add(1, std::memory_order_relaxed);
    vkq::PushOp1(vkq::CMD_END_SCENE, 0);
    if (replay::IsRecording()) {
        replay::Record r{};
        r.op = replay::REP_EndScene;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) { pipeline::EnqueueEndScene(); return D3D_OK; }
    return orig<PFN_EndScene, kSlot_EndScene>()(This);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_Clear(
    IDirect3DDevice9* This, DWORD Count, const D3DRECT* pRects,
    DWORD Flags, D3DCOLOR Color, float Z, DWORD Stencil) {
    gStats.clear.fetch_add(1, std::memory_order_relaxed);
    vkq::PushOp4(vkq::CMD_CLEAR, Count, Flags, Color, *(uint32_t*)&Z);
    if (replay::IsRecording()) {
        replay::Record r{};
        r.op = replay::REP_Clear;
        r.args[0] = Count;
        r.args[1] = Flags;
        r.args[2] = Color;
        std::memcpy(&r.args[3], &Z, sizeof(float));
        r.args[4] = Stencil;
        if (Count > 0 && pRects) {
            r.payloadOffset = replay::CurrentBuffer().AppendPayload(
                pRects, Count * sizeof(D3DRECT));
            r.payloadSize = Count * sizeof(D3DRECT);
        }
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueClear(Count, pRects, Flags, Color, Z, Stencil);
        return D3D_OK;
    }
    return orig<PFN_Clear, kSlot_Clear>()(This, Count, pRects, Flags, Color, Z, Stencil);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetTransform(
    IDirect3DDevice9* This, D3DTRANSFORMSTATETYPE State, const D3DMATRIX* pMatrix) {
    // Fixed-function transforms (world/view/proj). Skyrim uses shaders
    // mostly, so this is mainly legacy paths.
    if (kDedupEnabled && kDedup_Transform && pMatrix && (unsigned)State < kMaxTransformStates) {
        if (g_cache.transformSet[State] &&
            memcmp(g_cache.transform[State], pMatrix, sizeof(float) * 16) == 0) {
            gStats.dedupSkipped_Transform.fetch_add(1, std::memory_order_relaxed);
            return D3D_OK;
        }
        memcpy(g_cache.transform[State], pMatrix, sizeof(float) * 16);
        g_cache.transformSet[State] = true;
    }
    gStats.dedupPassed_Transform.fetch_add(1, std::memory_order_relaxed);
    if (replay::IsRecording() && pMatrix) {
        replay::Record r{};
        r.op = replay::REP_SetTransform;
        r.args[0] = (uint32_t)State;
        r.payloadOffset = replay::CurrentBuffer().AppendPayload(pMatrix, sizeof(D3DMATRIX));
        r.payloadSize = sizeof(D3DMATRIX);
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive() && pMatrix) {
        pipeline::EnqueueSetTransform((uint32_t)State, pMatrix);
        return D3D_OK;
    }
    return orig<PFN_SetTransform, kSlot_SetTransform>()(This, State, pMatrix);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetViewport(
    IDirect3DDevice9* This, const D3DVIEWPORT9* pViewport) {
    gStats.setViewport.fetch_add(1, std::memory_order_relaxed);
    if (kDedupEnabled && kDedup_Viewport && pViewport) {
        if (g_cache.viewportSet &&
            memcmp(&g_cache.viewport, pViewport, sizeof(D3DVIEWPORT9)) == 0) {
            gStats.dedupSkipped_Viewport.fetch_add(1, std::memory_order_relaxed);
            return D3D_OK;
        }
        memcpy(&g_cache.viewport, pViewport, sizeof(D3DVIEWPORT9));
        g_cache.viewportSet = true;
    }
    gStats.dedupPassed_Viewport.fetch_add(1, std::memory_order_relaxed);
    if (replay::IsRecording() && pViewport) {
        replay::Record r{};
        r.op = replay::REP_SetViewport;
        r.payloadOffset = replay::CurrentBuffer().AppendPayload(pViewport, sizeof(D3DVIEWPORT9));
        r.payloadSize = sizeof(D3DVIEWPORT9);
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive() && pViewport) {
        pipeline::EnqueueSetViewport(pViewport);
        return D3D_OK;
    }
    return orig<PFN_SetViewport, kSlot_SetViewport>()(This, pViewport);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetRenderState(
    IDirect3DDevice9* This, D3DRENDERSTATETYPE State, DWORD Value) {
    gStats.setRenderState.fetch_add(1, std::memory_order_relaxed);
    // Dedup: skip if state is already set to this value.
    if (kDedupEnabled && kDedup_RenderState && (unsigned)State < kMaxRenderStateTypes) {
        if (g_cache.renderStateSet[State] && g_cache.renderState[State] == Value) {
            gStats.dedupSkipped_RenderState.fetch_add(1, std::memory_order_relaxed);
            return D3D_OK;
        }
        g_cache.renderState[State] = Value;
        g_cache.renderStateSet[State] = true;
    }
    gStats.dedupPassed_RenderState.fetch_add(1, std::memory_order_relaxed);
    vkq::PushOp2(vkq::CMD_SET_RENDER_STATE, (uint32_t)State, Value);
    if (replay::IsRecording()) {
        replay::Record r{};
        r.op = replay::REP_SetRenderState;
        r.args[0] = (uint32_t)State;
        r.args[1] = Value;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueSetRenderState((uint32_t)State, Value);
        return D3D_OK;
    }
    return orig<PFN_SetRenderState, kSlot_SetRenderState>()(This, State, Value);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetSamplerState(
    IDirect3DDevice9* This, DWORD Sampler, D3DSAMPLERSTATETYPE Type, DWORD Value) {
    // The hottest call in Skyrim's render loop (~238k/sec). Most are redundant.
    if (kDedupEnabled && kDedup_SamplerState && Sampler < kMaxSamplerSlots && (unsigned)Type < kMaxSamplerStateTypes) {
        if (g_cache.samplerStateSet[Sampler][Type] && g_cache.samplerState[Sampler][Type] == Value) {
            gStats.dedupSkipped_SamplerState.fetch_add(1, std::memory_order_relaxed);
            return D3D_OK;
        }
        g_cache.samplerState[Sampler][Type] = Value;
        g_cache.samplerStateSet[Sampler][Type] = true;
    }
    gStats.dedupPassed_SamplerState.fetch_add(1, std::memory_order_relaxed);
    if (replay::IsRecording()) {
        replay::Record r{};
        r.op = replay::REP_SetSamplerState;
        r.args[0] = Sampler;
        r.args[1] = (uint32_t)Type;
        r.args[2] = Value;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueSetSamplerState(Sampler, (uint32_t)Type, Value);
        return D3D_OK;
    }
    return orig<PFN_SetSamplerState, kSlot_SetSamplerState>()(This, Sampler, Type, Value);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetTextureStageState(
    IDirect3DDevice9* This, DWORD Stage, D3DTEXTURESTAGESTATETYPE Type, DWORD Value) {
    if (kDedupEnabled && kDedup_TextureStageState && Stage < kMaxTextureStages && (unsigned)Type < kMaxTextureStageStateTypes) {
        if (g_cache.tssStateSet[Stage][Type] && g_cache.tssState[Stage][Type] == Value) {
            gStats.dedupSkipped_TextureStageState.fetch_add(1, std::memory_order_relaxed);
            return D3D_OK;
        }
        g_cache.tssState[Stage][Type] = Value;
        g_cache.tssStateSet[Stage][Type] = true;
    }
    gStats.dedupPassed_TextureStageState.fetch_add(1, std::memory_order_relaxed);
    if (replay::IsRecording()) {
        replay::Record r{};
        r.op = replay::REP_SetTextureStageState;
        r.args[0] = Stage;
        r.args[1] = (uint32_t)Type;
        r.args[2] = Value;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueSetTextureStageState(Stage, (uint32_t)Type, Value);
        return D3D_OK;
    }
    return orig<PFN_SetTextureStageState, kSlot_SetTextureStageState>()(This, Stage, Type, Value);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetTexture(
    IDirect3DDevice9* This, DWORD Stage, IDirect3DBaseTexture9* pTexture) {
    gStats.setTexture.fetch_add(1, std::memory_order_relaxed);
    // Dedup: skip if same texture is already bound to this stage.
    if (kDedupEnabled && kDedup_Texture && Stage < kMaxSamplerSlots) {
        if (g_cache.boundTextureSet[Stage] && g_cache.boundTexture[Stage] == pTexture) {
            gStats.dedupSkipped_Texture.fetch_add(1, std::memory_order_relaxed);
            return D3D_OK;
        }
        g_cache.boundTexture[Stage] = pTexture;
        g_cache.boundTextureSet[Stage] = true;
    }
    gStats.dedupPassed_Texture.fetch_add(1, std::memory_order_relaxed);
    vkq::PushOp2(vkq::CMD_SET_TEXTURE, Stage, (uint32_t)(uintptr_t)pTexture);
    if (replay::IsRecording()) {
        // Buffer record owns one AddRef on the resource. DoReplay's
        // REP_SetTexture case Releases it after orig<>(). Symmetric with
        // pipeline::EnqueueSetTexture's RecordAddRef.
        if (pTexture) pTexture->AddRef();
        replay::Record r{};
        r.op = replay::REP_SetTexture;
        r.args[0] = Stage;
        r.args[1] = (uint32_t)(uintptr_t)pTexture;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueSetTexture(Stage, pTexture);
        return D3D_OK;
    }
    return orig<PFN_SetTexture, kSlot_SetTexture>()(This, Stage, pTexture);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_DrawPrimitive(
    IDirect3DDevice9* This, D3DPRIMITIVETYPE PrimitiveType,
    UINT StartVertex, UINT PrimitiveCount) {
    gStats.drawPrimitive.fetch_add(1, std::memory_order_relaxed);
    gStats.totalPrimitives.fetch_add(PrimitiveCount, std::memory_order_relaxed);
    vkq::PushOp3(vkq::CMD_DRAW_PRIMITIVE, (uint32_t)PrimitiveType, StartVertex, PrimitiveCount);
    if (replay::IsRecording()) {
        replay::Record r{};
        r.op = replay::REP_DrawPrimitive;
        r.args[0] = (uint32_t)PrimitiveType;
        r.args[1] = StartVertex;
        r.args[2] = PrimitiveCount;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    // Stage 2: pipeline deferral — enqueue and return immediately. The
    // dispatcher thread (T_dispatch) calls orig<>() against the real D3D9
    // device on its own time. Skyrim doesn't use the return value of Draw*
    // (always D3D_OK in normal flow), so deferring is safe.
    if (pipeline::IsActive()) {
        pipeline::EnqueueDrawPrimitive((uint32_t)PrimitiveType, StartVertex, PrimitiveCount);
        return D3D_OK;
    }
    return orig<PFN_DrawPrimitive, kSlot_DrawPrimitive>()(This, PrimitiveType, StartVertex, PrimitiveCount);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_DrawIndexedPrimitive(
    IDirect3DDevice9* This, D3DPRIMITIVETYPE Type, INT BaseVertexIndex,
    UINT MinVertexIndex, UINT NumVertices, UINT startIndex, UINT primCount) {
    gStats.drawIndexedPrimitive.fetch_add(1, std::memory_order_relaxed);
    gStats.totalPrimitives.fetch_add(primCount, std::memory_order_relaxed);
    vkq::PushOp4(vkq::CMD_DRAW_INDEXED_PRIMITIVE,
                 (uint32_t)Type, (uint32_t)BaseVertexIndex,
                 NumVertices, primCount);
    if (replay::IsRecording()) {
        replay::Record r{};
        r.op = replay::REP_DrawIndexedPrimitive;
        r.args[0] = (uint32_t)Type;
        r.args[1] = (uint32_t)BaseVertexIndex;
        r.args[2] = MinVertexIndex;
        r.args[3] = NumVertices;
        r.args[4] = startIndex;
        r.args[5] = primCount;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueDrawIndexedPrimitive(
            (uint32_t)Type, BaseVertexIndex,
            MinVertexIndex, NumVertices, startIndex, primCount);
        return D3D_OK;
    }
    return orig<PFN_DrawIndexedPrimitive, kSlot_DrawIndexedPrimitive>()(
        This, Type, BaseVertexIndex, MinVertexIndex, NumVertices, startIndex, primCount);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetVertexShader(
    IDirect3DDevice9* This, IDirect3DVertexShader9* pShader) {
    gStats.setVertexShader.fetch_add(1, std::memory_order_relaxed);
    if (kDedupEnabled && kDedup_VertexShader && g_cache.boundVertexShaderSet && g_cache.boundVertexShader == pShader) {
        gStats.dedupSkipped_VertexShader.fetch_add(1, std::memory_order_relaxed);
        return D3D_OK;
    }
    g_cache.boundVertexShader = pShader;
    g_cache.boundVertexShaderSet = true;
    gStats.dedupPassed_VertexShader.fetch_add(1, std::memory_order_relaxed);
    if (replay::IsRecording()) {
        if (pShader) pShader->AddRef();
        replay::Record r{};
        r.op = replay::REP_SetVertexShader;
        r.args[0] = (uint32_t)(uintptr_t)pShader;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueSetVertexShader(pShader);
        return D3D_OK;
    }
    return orig<PFN_SetVertexShader, kSlot_SetVertexShader>()(This, pShader);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetVertexShaderConstantF(
    IDirect3DDevice9* This, UINT StartRegister, const float* pConstantData, UINT Vector4fCount) {
    gStats.setVertexShaderConstantF.fetch_add(1, std::memory_order_relaxed);

    // Per-register dedup with range trimming. For each Vector4f we're being
    // asked to set, compare bit-exactly against the cached value. If nothing
    // changed → skip the call entirely. If only registers [first, last]
    // changed → forward a smaller call covering just that range.
    if (kDedupEnabled && kDedup_VSConstantF && pConstantData && Vector4fCount > 0 &&
        StartRegister + Vector4fCount <= kMaxVSConstantRegisters) {

        int firstChanged = -1, lastChanged = -1;
        for (UINT i = 0; i < Vector4fCount; ++i) {
            const float* incoming = pConstantData + i * 4;
            float* cached = g_cache.vsConstantF[StartRegister + i];
            if (!g_cache.vsConstantFSet[StartRegister + i] ||
                memcmp(cached, incoming, 16) != 0) {
                if (firstChanged < 0) firstChanged = (int)i;
                lastChanged = (int)i;
                memcpy(cached, incoming, 16);
                g_cache.vsConstantFSet[StartRegister + i] = true;
            }
        }

        if (firstChanged < 0) {
            // Nothing changed — skip the entire call (also skips recording).
            gStats.dedupSkipped_VSConstantF.fetch_add(1, std::memory_order_relaxed);
            return D3D_OK;
        }
        const UINT trimmedStart = StartRegister + firstChanged;
        const UINT trimmedCount = (UINT)(lastChanged - firstChanged + 1);
        if (trimmedStart != StartRegister || trimmedCount != Vector4fCount) {
            // Forward a smaller call covering just the changed range.
            gStats.dedupTrimmed_VSConstantF.fetch_add(1, std::memory_order_relaxed);
            const float* trimmedData = pConstantData + firstChanged * 4;
            if (replay::IsRecording()) {
                replay::Record r{};
                r.op = replay::REP_SetVertexShaderConstantF;
                r.args[0] = trimmedStart;
                r.args[1] = trimmedCount;
                r.payloadOffset = replay::CurrentBuffer().AppendPayload(
                    trimmedData, trimmedCount * sizeof(float) * 4);
                r.payloadSize = trimmedCount * sizeof(float) * 4;
                replay::CurrentBuffer().records.push_back(r);
                return D3D_OK;
            }
            if (pipeline::IsActive()) {
                pipeline::EnqueueSetVertexShaderConstantF(trimmedStart, trimmedData, trimmedCount);
                return D3D_OK;
            }
            return orig<PFN_SetVertexShaderConstantF, kSlot_SetVertexShaderConstantF>()(
                This, trimmedStart, trimmedData, trimmedCount);
        }
    }
    gStats.dedupPassed_VSConstantF.fetch_add(1, std::memory_order_relaxed);
    if (replay::IsRecording() && pConstantData && Vector4fCount > 0) {
        replay::Record r{};
        r.op = replay::REP_SetVertexShaderConstantF;
        r.args[0] = StartRegister;
        r.args[1] = Vector4fCount;
        r.payloadOffset = replay::CurrentBuffer().AppendPayload(
            pConstantData, Vector4fCount * sizeof(float) * 4);
        r.payloadSize = Vector4fCount * sizeof(float) * 4;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive() && pConstantData && Vector4fCount > 0) {
        pipeline::EnqueueSetVertexShaderConstantF(StartRegister, pConstantData, Vector4fCount);
        return D3D_OK;
    }
    return orig<PFN_SetVertexShaderConstantF, kSlot_SetVertexShaderConstantF>()(
        This, StartRegister, pConstantData, Vector4fCount);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetPixelShader(
    IDirect3DDevice9* This, IDirect3DPixelShader9* pShader) {
    gStats.setPixelShader.fetch_add(1, std::memory_order_relaxed);
    if (kDedupEnabled && kDedup_PixelShader && g_cache.boundPixelShaderSet && g_cache.boundPixelShader == pShader) {
        gStats.dedupSkipped_PixelShader.fetch_add(1, std::memory_order_relaxed);
        return D3D_OK;
    }
    g_cache.boundPixelShader = pShader;
    g_cache.boundPixelShaderSet = true;
    gStats.dedupPassed_PixelShader.fetch_add(1, std::memory_order_relaxed);
    if (replay::IsRecording()) {
        if (pShader) pShader->AddRef();
        replay::Record r{};
        r.op = replay::REP_SetPixelShader;
        r.args[0] = (uint32_t)(uintptr_t)pShader;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueSetPixelShader(pShader);
        return D3D_OK;
    }
    return orig<PFN_SetPixelShader, kSlot_SetPixelShader>()(This, pShader);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetPixelShaderConstantF(
    IDirect3DDevice9* This, UINT StartRegister, const float* pConstantData, UINT Vector4fCount) {
    gStats.setPixelShaderConstantF.fetch_add(1, std::memory_order_relaxed);

    if (kDedupEnabled && kDedup_PSConstantF && pConstantData && Vector4fCount > 0 &&
        StartRegister + Vector4fCount <= kMaxPSConstantRegisters) {

        int firstChanged = -1, lastChanged = -1;
        for (UINT i = 0; i < Vector4fCount; ++i) {
            const float* incoming = pConstantData + i * 4;
            float* cached = g_cache.psConstantF[StartRegister + i];
            if (!g_cache.psConstantFSet[StartRegister + i] ||
                memcmp(cached, incoming, 16) != 0) {
                if (firstChanged < 0) firstChanged = (int)i;
                lastChanged = (int)i;
                memcpy(cached, incoming, 16);
                g_cache.psConstantFSet[StartRegister + i] = true;
            }
        }

        if (firstChanged < 0) {
            gStats.dedupSkipped_PSConstantF.fetch_add(1, std::memory_order_relaxed);
            return D3D_OK;
        }
        const UINT trimmedStart = StartRegister + firstChanged;
        const UINT trimmedCount = (UINT)(lastChanged - firstChanged + 1);
        if (trimmedStart != StartRegister || trimmedCount != Vector4fCount) {
            gStats.dedupTrimmed_PSConstantF.fetch_add(1, std::memory_order_relaxed);
            const float* trimmedData = pConstantData + firstChanged * 4;
            if (replay::IsRecording()) {
                replay::Record r{};
                r.op = replay::REP_SetPixelShaderConstantF;
                r.args[0] = trimmedStart;
                r.args[1] = trimmedCount;
                r.payloadOffset = replay::CurrentBuffer().AppendPayload(
                    trimmedData, trimmedCount * sizeof(float) * 4);
                r.payloadSize = trimmedCount * sizeof(float) * 4;
                replay::CurrentBuffer().records.push_back(r);
                return D3D_OK;
            }
            if (pipeline::IsActive()) {
                pipeline::EnqueueSetPixelShaderConstantF(trimmedStart, trimmedData, trimmedCount);
                return D3D_OK;
            }
            return orig<PFN_SetPixelShaderConstantF, kSlot_SetPixelShaderConstantF>()(
                This, trimmedStart, trimmedData, trimmedCount);
        }
    }
    gStats.dedupPassed_PSConstantF.fetch_add(1, std::memory_order_relaxed);
    if (replay::IsRecording() && pConstantData && Vector4fCount > 0) {
        replay::Record r{};
        r.op = replay::REP_SetPixelShaderConstantF;
        r.args[0] = StartRegister;
        r.args[1] = Vector4fCount;
        r.payloadOffset = replay::CurrentBuffer().AppendPayload(
            pConstantData, Vector4fCount * sizeof(float) * 4);
        r.payloadSize = Vector4fCount * sizeof(float) * 4;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive() && pConstantData && Vector4fCount > 0) {
        pipeline::EnqueueSetPixelShaderConstantF(StartRegister, pConstantData, Vector4fCount);
        return D3D_OK;
    }
    return orig<PFN_SetPixelShaderConstantF, kSlot_SetPixelShaderConstantF>()(
        This, StartRegister, pConstantData, Vector4fCount);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetStreamSource(
    IDirect3DDevice9* This, UINT StreamNumber,
    IDirect3DVertexBuffer9* pStreamData, UINT OffsetInBytes, UINT Stride) {
    gStats.setStreamSource.fetch_add(1, std::memory_order_relaxed);
    if (kDedupEnabled && kDedup_StreamSource && StreamNumber < kMaxStreams) {
        const StreamBinding& cur = g_cache.stream[StreamNumber];
        if (g_cache.streamSet[StreamNumber] &&
            cur.vb == pStreamData && cur.offset == OffsetInBytes && cur.stride == Stride) {
            gStats.dedupSkipped_StreamSource.fetch_add(1, std::memory_order_relaxed);
            return D3D_OK;
        }
        g_cache.stream[StreamNumber] = { pStreamData, OffsetInBytes, Stride };
        g_cache.streamSet[StreamNumber] = true;
    }
    gStats.dedupPassed_StreamSource.fetch_add(1, std::memory_order_relaxed);
    if (replay::IsRecording()) {
        if (pStreamData) pStreamData->AddRef();
        replay::Record r{};
        r.op = replay::REP_SetStreamSource;
        r.args[0] = StreamNumber;
        r.args[1] = (uint32_t)(uintptr_t)pStreamData;
        r.args[2] = OffsetInBytes;
        r.args[3] = Stride;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueSetStreamSource(StreamNumber, pStreamData, OffsetInBytes, Stride);
        return D3D_OK;
    }
    return orig<PFN_SetStreamSource, kSlot_SetStreamSource>()(
        This, StreamNumber, pStreamData, OffsetInBytes, Stride);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetStreamSourceFreq(
    IDirect3DDevice9* This, UINT StreamNumber, UINT Setting) {
    // The #1 hottest unwrapped pass-through observed in Skyrim — 38k+/s.
    if (kDedupEnabled && kDedup_StreamSourceFreq && StreamNumber < kMaxStreams) {
        if (g_cache.streamFreqSet[StreamNumber] && g_cache.streamFreq[StreamNumber] == Setting) {
            gStats.dedupSkipped_StreamSourceFreq.fetch_add(1, std::memory_order_relaxed);
            return D3D_OK;
        }
        g_cache.streamFreq[StreamNumber] = Setting;
        g_cache.streamFreqSet[StreamNumber] = true;
    }
    gStats.dedupPassed_StreamSourceFreq.fetch_add(1, std::memory_order_relaxed);
    if (replay::IsRecording()) {
        replay::Record r{};
        r.op = replay::REP_SetStreamSourceFreq;
        r.args[0] = StreamNumber;
        r.args[1] = Setting;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueSetStreamSourceFreq(StreamNumber, Setting);
        return D3D_OK;
    }
    return orig<PFN_SetStreamSourceFreq, kSlot_SetStreamSourceFreq>()(This, StreamNumber, Setting);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetIndices(
    IDirect3DDevice9* This, IDirect3DIndexBuffer9* pIndexData) {
    gStats.setIndices.fetch_add(1, std::memory_order_relaxed);
    if (kDedupEnabled && kDedup_Indices) {
        if (g_cache.boundIndicesSet && g_cache.boundIndices == pIndexData) {
            gStats.dedupSkipped_Indices.fetch_add(1, std::memory_order_relaxed);
            return D3D_OK;
        }
        g_cache.boundIndices = pIndexData;
        g_cache.boundIndicesSet = true;
    }
    gStats.dedupPassed_Indices.fetch_add(1, std::memory_order_relaxed);
    if (replay::IsRecording()) {
        if (pIndexData) pIndexData->AddRef();
        replay::Record r{};
        r.op = replay::REP_SetIndices;
        r.args[0] = (uint32_t)(uintptr_t)pIndexData;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueSetIndices(pIndexData);
        return D3D_OK;
    }
    return orig<PFN_SetIndices, kSlot_SetIndices>()(This, pIndexData);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetVertexDeclaration(
    IDirect3DDevice9* This, IDirect3DVertexDeclaration9* pDecl) {
    if (kDedupEnabled && kDedup_VertexDeclaration) {
        if (g_cache.boundVertexDeclSet && g_cache.boundVertexDecl == (void*)pDecl) {
            gStats.dedupSkipped_VertexDeclaration.fetch_add(1, std::memory_order_relaxed);
            return D3D_OK;
        }
        g_cache.boundVertexDecl = (void*)pDecl;
        g_cache.boundVertexDeclSet = true;
    }
    gStats.dedupPassed_VertexDeclaration.fetch_add(1, std::memory_order_relaxed);
    if (replay::IsRecording()) {
        if (pDecl) pDecl->AddRef();
        replay::Record r{};
        r.op = replay::REP_SetVertexDeclaration;
        r.args[0] = (uint32_t)(uintptr_t)pDecl;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueSetVertexDeclaration(pDecl);
        return D3D_OK;
    }
    return orig<PFN_SetVertexDeclaration, kSlot_SetVertexDeclaration>()(This, pDecl);
}

// Stage 3: SetRenderTarget / SetDepthStencilSurface added to typed wrappers
// so they can be deferred through the pipeline. These weren't previously
// wrapped (slot 37 / 39 ran on generic counter thunks, hitting D3D9 directly),
// which broke pipeline ordering: deferred draws would land on whatever RT
// the latest sync SetRenderTarget had established, not the RT intended at
// draw-record time. Deferring these closes the gap.

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetRenderTarget(
    IDirect3DDevice9* This, DWORD RenderTargetIndex, IDirect3DSurface9* pRenderTarget) {
    if (replay::IsRecording()) {
        if (pRenderTarget) pRenderTarget->AddRef();
        replay::Record r{};
        r.op = replay::REP_SetRenderTarget;
        r.args[0] = RenderTargetIndex;
        r.args[1] = (uint32_t)(uintptr_t)pRenderTarget;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueSetRenderTarget(RenderTargetIndex, pRenderTarget);
        return D3D_OK;
    }
    return orig<PFN_SetRenderTarget, kSlot_SetRenderTarget>()(This, RenderTargetIndex, pRenderTarget);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetDepthStencilSurface(
    IDirect3DDevice9* This, IDirect3DSurface9* pNewZStencil) {
    if (replay::IsRecording()) {
        if (pNewZStencil) pNewZStencil->AddRef();
        replay::Record r{};
        r.op = replay::REP_SetDepthStencilSurface;
        r.args[0] = (uint32_t)(uintptr_t)pNewZStencil;
        replay::CurrentBuffer().records.push_back(r);
        return D3D_OK;
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueSetDepthStencilSurface(pNewZStencil);
        return D3D_OK;
    }
    return orig<PFN_SetDepthStencilSurface, kSlot_SetDepthStencilSurface>()(This, pNewZStencil);
}

// =============================================================================
// Get* wrappers — runtime debugger for "where is Skyrim reading D3D9 state"
// =============================================================================
//
// Each wrapper captures the TESV.exe retaddr (the instruction immediately
// after the vtable call) and hands it to readprofiler::Note(). Behavior is
// otherwise identical to the original orig<>() call: same args, same return,
// same out-params written. No state cached, no deferral.
//
// The motivation: under the deferred-Set* pipeline, Get* methods read the
// REAL device state which lags the queued (not-yet-dispatched) Set* ops.
// Save/restore patterns (`Get → Set(temp) → ... → Set(saved)`) silently
// store the stale value as `saved`. The periodic [ReadProf] log line shows
// the top TESV.exe call sites for each Get* — those are the candidate
// glitch sources to inspect in IDA / fix.
#define MIRROR_GET_WRAPPER_DEF(NAME, PFN, SLOT, READID, SIG, ARGS) \
    extern "C" HRESULT STDMETHODCALLTYPE Mirror_##NAME SIG { \
        readprofiler::Note(readprofiler::READID, \
                           (uint32_t)(uintptr_t)_ReturnAddress()); \
        return orig<PFN, SLOT>() ARGS; \
    }

// Mirror_GetRenderTarget — special-cased (not via the macro) because under
// the active pipeline we MUST return the queued state, not the real device's
// (lagging) state. Pattern observed via the read profiler: function at
// 0x00F874C0 calls GetRenderTarget+GetDesc to size buffers; with stale data
// it sizes against the wrong RT → visual glitch. The shadow holds an
// AddRef'd pointer for as long as it's the queued RT, so:
//   1. The pointer is alive (refcount-safe).
//   2. The pointer reflects what Skyrim queued, not what the dispatcher has
//      already drained.
extern "C" HRESULT STDMETHODCALLTYPE Mirror_GetRenderTarget(
    IDirect3DDevice9* This, DWORD index, IDirect3DSurface9** ppRT) {
    readprofiler::Note(readprofiler::READ_GetRenderTarget,
                       (uint32_t)(uintptr_t)_ReturnAddress());
    if (ppRT && pipeline::IsActive()) {
        // Shadow stores a raw ptr; the buffer record's AddRef keeps it alive
        // while it's the latest queued RT. Add a fresh ref for the caller —
        // GetRenderTarget contract is "returned ptr is AddRef'd; caller
        // Releases".
        IDirect3DSurface9* shadow =
            static_cast<IDirect3DSurface9*>(pipeline::GetShadowRenderTarget(index));
        if (shadow) {
            shadow->AddRef();
            *ppRT = shadow;
            return D3D_OK;
        }
        // Shadow hasn't been populated yet (no SetRenderTarget issued for
        // this index). Fall through to the real device, which still has the
        // initial RT (the back buffer set up by CreateDevice).
    }
    return orig<PFN_GetRenderTarget, kSlot_GetRenderTarget>()(This, index, ppRT);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_GetDepthStencilSurface(
    IDirect3DDevice9* This, IDirect3DSurface9** ppDS) {
    readprofiler::Note(readprofiler::READ_GetDepthStencilSurface,
                       (uint32_t)(uintptr_t)_ReturnAddress());
    if (ppDS && pipeline::IsActive()) {
        IDirect3DSurface9* shadow =
            static_cast<IDirect3DSurface9*>(pipeline::GetShadowDepthStencilSurface());
        if (shadow) {
            shadow->AddRef();
            *ppDS = shadow;
            return D3D_OK;
        }
    }
    return orig<PFN_GetDepthStencilSurface, kSlot_GetDepthStencilSurface>()(This, ppDS);
}

MIRROR_GET_WRAPPER_DEF(GetTransform, PFN_GetTransform, kSlot_GetTransform,
    READ_GetTransform,
    (IDirect3DDevice9* This, D3DTRANSFORMSTATETYPE State, D3DMATRIX* pMatrix),
    (This, State, pMatrix))

MIRROR_GET_WRAPPER_DEF(GetViewport, PFN_GetViewport, kSlot_GetViewport,
    READ_GetViewport,
    (IDirect3DDevice9* This, D3DVIEWPORT9* pViewport),
    (This, pViewport))

MIRROR_GET_WRAPPER_DEF(GetRenderState, PFN_GetRenderState, kSlot_GetRenderState,
    READ_GetRenderState,
    (IDirect3DDevice9* This, D3DRENDERSTATETYPE State, DWORD* pValue),
    (This, State, pValue))

MIRROR_GET_WRAPPER_DEF(GetTexture, PFN_GetTexture, kSlot_GetTexture,
    READ_GetTexture,
    (IDirect3DDevice9* This, DWORD Stage, IDirect3DBaseTexture9** ppTex),
    (This, Stage, ppTex))

MIRROR_GET_WRAPPER_DEF(GetTextureStageState, PFN_GetTextureStageState,
    kSlot_GetTextureStageState, READ_GetTextureStageState,
    (IDirect3DDevice9* This, DWORD Stage, D3DTEXTURESTAGESTATETYPE Type, DWORD* pValue),
    (This, Stage, Type, pValue))

MIRROR_GET_WRAPPER_DEF(GetSamplerState, PFN_GetSamplerState, kSlot_GetSamplerState,
    READ_GetSamplerState,
    (IDirect3DDevice9* This, DWORD Sampler, D3DSAMPLERSTATETYPE Type, DWORD* pValue),
    (This, Sampler, Type, pValue))

MIRROR_GET_WRAPPER_DEF(GetVertexDeclaration, PFN_GetVertexDeclaration,
    kSlot_GetVertexDeclaration, READ_GetVertexDeclaration,
    (IDirect3DDevice9* This, IDirect3DVertexDeclaration9** ppDecl),
    (This, ppDecl))

MIRROR_GET_WRAPPER_DEF(GetVertexShader, PFN_GetVertexShader, kSlot_GetVertexShader,
    READ_GetVertexShader,
    (IDirect3DDevice9* This, IDirect3DVertexShader9** ppShader),
    (This, ppShader))

MIRROR_GET_WRAPPER_DEF(GetVertexShaderConstantF, PFN_GetVertexShaderConstantF,
    kSlot_GetVertexShaderConstantF, READ_GetVertexShaderConstantF,
    (IDirect3DDevice9* This, UINT StartReg, float* pData, UINT Vector4fCount),
    (This, StartReg, pData, Vector4fCount))

MIRROR_GET_WRAPPER_DEF(GetStreamSource, PFN_GetStreamSource, kSlot_GetStreamSource,
    READ_GetStreamSource,
    (IDirect3DDevice9* This, UINT StreamNumber, IDirect3DVertexBuffer9** ppVB,
     UINT* pOffset, UINT* pStride),
    (This, StreamNumber, ppVB, pOffset, pStride))

MIRROR_GET_WRAPPER_DEF(GetIndices, PFN_GetIndices, kSlot_GetIndices,
    READ_GetIndices,
    (IDirect3DDevice9* This, IDirect3DIndexBuffer9** ppIB),
    (This, ppIB))

MIRROR_GET_WRAPPER_DEF(GetPixelShader, PFN_GetPixelShader, kSlot_GetPixelShader,
    READ_GetPixelShader,
    (IDirect3DDevice9* This, IDirect3DPixelShader9** ppShader),
    (This, ppShader))

MIRROR_GET_WRAPPER_DEF(GetPixelShaderConstantF, PFN_GetPixelShaderConstantF,
    kSlot_GetPixelShaderConstantF, READ_GetPixelShaderConstantF,
    (IDirect3DDevice9* This, UINT StartReg, float* pData, UINT Vector4fCount),
    (This, StartReg, pData, Vector4fCount))

#undef MIRROR_GET_WRAPPER_DEF

// Stage 6 wrappers — DrawPrimitiveUP + SetFVF deferred so UI/HUD doesn't run
// against stale device state.
extern "C" HRESULT STDMETHODCALLTYPE Mirror_DrawPrimitiveUP(
    IDirect3DDevice9* This, D3DPRIMITIVETYPE primType, UINT primCount,
    const void* pVertexData, UINT stride) {
    if (replay::IsRecording()) {
        // Hot-sub recording path doesn't yet support DrawPrimitiveUP (it
        // wasn't in the original Op set); fall through to direct dispatch
        // when in that mode. Pipeline path below is the active one.
        return orig<PFN_DrawPrimitiveUP, kSlot_DrawPrimitiveUP>()(
            This, primType, primCount, pVertexData, stride);
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueDrawPrimitiveUP((uint32_t)primType, primCount, pVertexData, stride);
        return D3D_OK;
    }
    return orig<PFN_DrawPrimitiveUP, kSlot_DrawPrimitiveUP>()(
        This, primType, primCount, pVertexData, stride);
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_SetFVF(IDirect3DDevice9* This, DWORD FVF) {
    if (replay::IsRecording()) {
        return orig<PFN_SetFVF, kSlot_SetFVF>()(This, FVF);
    }
    if (pipeline::IsActive()) {
        pipeline::EnqueueSetFVF(FVF);
        return D3D_OK;
    }
    return orig<PFN_SetFVF, kSlot_SetFVF>()(This, FVF);
}

// -------- Resource creation wrappers --------
//
// These chain to the original first to get the D3D9 object back, then ALSO
// create a parallel Vulkan resource. The mapping is logged for now; the
// actual VkImage / VkBuffer allocation is a Phase 6.1 deliverable.

extern "C" HRESULT STDMETHODCALLTYPE Mirror_CreateTexture(
    IDirect3DDevice9* This, UINT Width, UINT Height, UINT Levels, DWORD Usage,
    D3DFORMAT Format, D3DPOOL Pool,
    IDirect3DTexture9** ppTexture, HANDLE* pSharedHandle) {
    HRESULT hr = orig<PFN_CreateTexture, kSlot_CreateTexture>()(
        This, Width, Height, Levels, Usage, Format, Pool, ppTexture, pSharedHandle);
    gStats.createTexture.fetch_add(1, std::memory_order_relaxed);
    if (SUCCEEDED(hr) && ppTexture && *ppTexture) {
        const uint64_t n = gResources.textures.fetch_add(1, std::memory_order_relaxed) + 1;
        resmirror::NoteTexture(*ppTexture, Width, Height, Levels, Usage, (uint32_t)Format, (uint32_t)Pool);
        if (n == 1 || n == 100 || n == 1000 || (n % 5000) == 0) {
            OD_LOG("[MIRROR] CreateTexture #%llu: %ux%u L=%u fmt=%d pool=%d -> %p",
                   n, Width, Height, Levels, (int)Format, (int)Pool, *ppTexture);
        }
    }
    return hr;
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_CreateVertexBuffer(
    IDirect3DDevice9* This, UINT Length, DWORD Usage, DWORD FVF, D3DPOOL Pool,
    IDirect3DVertexBuffer9** ppVertexBuffer, HANDLE* pSharedHandle) {
    HRESULT hr = orig<PFN_CreateVertexBuffer, kSlot_CreateVertexBuffer>()(
        This, Length, Usage, FVF, Pool, ppVertexBuffer, pSharedHandle);
    if (SUCCEEDED(hr) && ppVertexBuffer && *ppVertexBuffer) {
        const uint64_t n = gResources.vertexBuffers.fetch_add(1, std::memory_order_relaxed) + 1;
        resmirror::NoteVertexBuffer(*ppVertexBuffer, Length, Usage, FVF, (uint32_t)Pool);
        if (n == 1 || n == 100 || n == 1000 || (n % 5000) == 0) {
            OD_LOG("[MIRROR] CreateVertexBuffer #%llu: len=%u FVF=0x%08X pool=%d -> %p",
                   n, Length, FVF, (int)Pool, *ppVertexBuffer);
        }
    }
    return hr;
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_CreateIndexBuffer(
    IDirect3DDevice9* This, UINT Length, DWORD Usage, D3DFORMAT Format, D3DPOOL Pool,
    IDirect3DIndexBuffer9** ppIndexBuffer, HANDLE* pSharedHandle) {
    HRESULT hr = orig<PFN_CreateIndexBuffer, kSlot_CreateIndexBuffer>()(
        This, Length, Usage, Format, Pool, ppIndexBuffer, pSharedHandle);
    if (SUCCEEDED(hr) && ppIndexBuffer && *ppIndexBuffer) {
        const uint64_t n = gResources.indexBuffers.fetch_add(1, std::memory_order_relaxed) + 1;
        resmirror::NoteIndexBuffer(*ppIndexBuffer, Length, Usage, (uint32_t)Format, (uint32_t)Pool);
        if (n == 1 || n == 100 || n == 1000 || (n % 5000) == 0) {
            OD_LOG("[MIRROR] CreateIndexBuffer #%llu: len=%u fmt=%d pool=%d -> %p",
                   n, Length, (int)Format, (int)Pool, *ppIndexBuffer);
        }
    }
    return hr;
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_CreateVertexShader(
    IDirect3DDevice9* This, const DWORD* pFunction, IDirect3DVertexShader9** ppShader) {
    HRESULT hr = orig<PFN_CreateVertexShader, kSlot_CreateVertexShader>()(This, pFunction, ppShader);
    if (SUCCEEDED(hr) && ppShader && *ppShader) {
        const uint64_t n = gResources.vertexShaders.fetch_add(1, std::memory_order_relaxed) + 1;
        // Capture bytecode for future DXBC->SPIR-V translation. Length is
        // computed inside ResourceMirror via the 0x0000FFFF END token.
        resmirror::NoteVertexShader(*ppShader, pFunction, 0);
        if (n == 1 || n == 10 || n == 100 || (n % 500) == 0) {
            size_t dwordsLen = 0;
            if (pFunction) {
                const DWORD* p = pFunction;
                while (*p != 0x0000FFFF && dwordsLen < 8192) { ++p; ++dwordsLen; }
            }
            OD_LOG("[MIRROR] CreateVertexShader #%llu: %zu bytecode dwords -> %p",
                   n, dwordsLen, *ppShader);
        }
    }
    return hr;
}

extern "C" HRESULT STDMETHODCALLTYPE Mirror_CreatePixelShader(
    IDirect3DDevice9* This, const DWORD* pFunction, IDirect3DPixelShader9** ppShader) {
    HRESULT hr = orig<PFN_CreatePixelShader, kSlot_CreatePixelShader>()(This, pFunction, ppShader);
    if (SUCCEEDED(hr) && ppShader && *ppShader) {
        const uint64_t n = gResources.pixelShaders.fetch_add(1, std::memory_order_relaxed) + 1;
        resmirror::NotePixelShader(*ppShader, pFunction, 0);
        if (n == 1 || n == 10 || n == 100 || (n % 500) == 0) {
            size_t dwordsLen = 0;
            if (pFunction) {
                const DWORD* p = pFunction;
                while (*p != 0x0000FFFF && dwordsLen < 8192) { ++p; ++dwordsLen; }
            }
            OD_LOG("[MIRROR] CreatePixelShader #%llu: %zu bytecode dwords -> %p",
                   n, dwordsLen, *ppShader);
        }
    }
    return hr;
}

// =============================================================================
// Replay — issues a recorded Buffer through the orig<> trampolines.
// =============================================================================
//
// Lives inside this anon namespace (where orig<> is visible) and is registered
// as the implementation for `overdrive::replay::Replay()` via a function-
// pointer hook set at static-init time. Replay dispatches directly to orig<> —
// it does NOT go through the Mirror_* wrappers (which would re-enter recording
// mode or trigger dedup).
//
// Caller must NOT be in recording mode. Buffer is read-only here.
HRESULT DoReplay(IDirect3DDevice9* dev, const overdrive::replay::Buffer& buf) {
    using namespace overdrive::replay;
    for (const Record& r : buf.records) {
        switch (r.op) {
        case REP_BeginScene:
            orig<PFN_BeginScene, kSlot_BeginScene>()(dev);
            break;
        case REP_EndScene:
            orig<PFN_EndScene, kSlot_EndScene>()(dev);
            break;
        case REP_Clear: {
            const D3DRECT* rects = r.payloadSize > 0
                ? reinterpret_cast<const D3DRECT*>(buf.payload.data() + r.payloadOffset)
                : nullptr;
            float z;
            std::memcpy(&z, &r.args[3], sizeof(float));
            orig<PFN_Clear, kSlot_Clear>()(
                dev, r.args[0], rects, r.args[1], (D3DCOLOR)r.args[2], z, r.args[4]);
            break;
        }
        case REP_SetTransform: {
            const D3DMATRIX* m = reinterpret_cast<const D3DMATRIX*>(
                buf.payload.data() + r.payloadOffset);
            orig<PFN_SetTransform, kSlot_SetTransform>()(
                dev, (D3DTRANSFORMSTATETYPE)r.args[0], m);
            break;
        }
        case REP_SetViewport: {
            const D3DVIEWPORT9* vp = reinterpret_cast<const D3DVIEWPORT9*>(
                buf.payload.data() + r.payloadOffset);
            orig<PFN_SetViewport, kSlot_SetViewport>()(dev, vp);
            break;
        }
        case REP_SetRenderState:
            orig<PFN_SetRenderState, kSlot_SetRenderState>()(
                dev, (D3DRENDERSTATETYPE)r.args[0], r.args[1]);
            break;
        case REP_SetSamplerState:
            orig<PFN_SetSamplerState, kSlot_SetSamplerState>()(
                dev, r.args[0], (D3DSAMPLERSTATETYPE)r.args[1], r.args[2]);
            break;
        case REP_SetTextureStageState:
            orig<PFN_SetTextureStageState, kSlot_SetTextureStageState>()(
                dev, r.args[0], (D3DTEXTURESTAGESTATETYPE)r.args[1], r.args[2]);
            break;
        case REP_SetTexture: {
            auto* tex = reinterpret_cast<IDirect3DBaseTexture9*>((uintptr_t)r.args[1]);
            orig<PFN_SetTexture, kSlot_SetTexture>()(dev, r.args[0], tex);
            // Release the AddRef the EnqueueSetTexture took at record time
            // — the buffer record owns the ref to keep `tex` alive across
            // the Enqueue→Dispatch latency window.
            if (tex) tex->Release();
            break;
        }
        case REP_DrawPrimitive:
            orig<PFN_DrawPrimitive, kSlot_DrawPrimitive>()(
                dev, (D3DPRIMITIVETYPE)r.args[0], r.args[1], r.args[2]);
            break;
        case REP_DrawIndexedPrimitive:
            orig<PFN_DrawIndexedPrimitive, kSlot_DrawIndexedPrimitive>()(
                dev, (D3DPRIMITIVETYPE)r.args[0], (INT)r.args[1],
                r.args[2], r.args[3], r.args[4], r.args[5]);
            break;
        case REP_SetVertexShader: {
            auto* sh = reinterpret_cast<IDirect3DVertexShader9*>((uintptr_t)r.args[0]);
            orig<PFN_SetVertexShader, kSlot_SetVertexShader>()(dev, sh);
            if (sh) sh->Release();
            break;
        }
        case REP_SetVertexShaderConstantF: {
            const float* data = reinterpret_cast<const float*>(
                buf.payload.data() + r.payloadOffset);
            orig<PFN_SetVertexShaderConstantF, kSlot_SetVertexShaderConstantF>()(
                dev, r.args[0], data, r.args[1]);
            break;
        }
        case REP_SetPixelShader: {
            auto* sh = reinterpret_cast<IDirect3DPixelShader9*>((uintptr_t)r.args[0]);
            orig<PFN_SetPixelShader, kSlot_SetPixelShader>()(dev, sh);
            if (sh) sh->Release();
            break;
        }
        case REP_SetPixelShaderConstantF: {
            const float* data = reinterpret_cast<const float*>(
                buf.payload.data() + r.payloadOffset);
            orig<PFN_SetPixelShaderConstantF, kSlot_SetPixelShaderConstantF>()(
                dev, r.args[0], data, r.args[1]);
            break;
        }
        case REP_SetStreamSource: {
            auto* vb = reinterpret_cast<IDirect3DVertexBuffer9*>((uintptr_t)r.args[1]);
            orig<PFN_SetStreamSource, kSlot_SetStreamSource>()(
                dev, r.args[0], vb, r.args[2], r.args[3]);
            if (vb) vb->Release();
            break;
        }
        case REP_SetStreamSourceFreq:
            orig<PFN_SetStreamSourceFreq, kSlot_SetStreamSourceFreq>()(
                dev, r.args[0], r.args[1]);
            break;
        case REP_SetIndices: {
            auto* ib = reinterpret_cast<IDirect3DIndexBuffer9*>((uintptr_t)r.args[0]);
            orig<PFN_SetIndices, kSlot_SetIndices>()(dev, ib);
            if (ib) ib->Release();
            break;
        }
        case REP_SetVertexDeclaration: {
            auto* decl = reinterpret_cast<IDirect3DVertexDeclaration9*>((uintptr_t)r.args[0]);
            orig<PFN_SetVertexDeclaration, kSlot_SetVertexDeclaration>()(dev, decl);
            if (decl) decl->Release();
            break;
        }
        case REP_SetRenderTarget: {
            auto* surf = reinterpret_cast<IDirect3DSurface9*>((uintptr_t)r.args[1]);
            orig<PFN_SetRenderTarget, kSlot_SetRenderTarget>()(dev, r.args[0], surf);
            if (surf) surf->Release();
            break;
        }
        case REP_SetDepthStencilSurface: {
            auto* surf = reinterpret_cast<IDirect3DSurface9*>((uintptr_t)r.args[0]);
            orig<PFN_SetDepthStencilSurface, kSlot_SetDepthStencilSurface>()(dev, surf);
            if (surf) surf->Release();
            break;
        }
        case REP_DrawPrimitiveUP: {
            const void* vertexData = r.payloadSize > 0
                ? reinterpret_cast<const void*>(buf.payload.data() + r.payloadOffset)
                : nullptr;
            orig<PFN_DrawPrimitiveUP, kSlot_DrawPrimitiveUP>()(
                dev, (D3DPRIMITIVETYPE)r.args[0], r.args[1], vertexData, r.args[2]);
            break;
        }
        case REP_SetFVF:
            orig<PFN_SetFVF, kSlot_SetFVF>()(dev, r.args[0]);
            break;
        }
    }
    if (!buf.records.empty()) {
        overdrive::replay::NoteReplayedCount(static_cast<uint32_t>(buf.records.size()));
    }
    return D3D_OK;
}

// Static-init: register DoReplay as the implementation for replay::Replay().
struct ReplayInstallOnLoad {
    ReplayInstallOnLoad() { overdrive::replay::SetReplayImpl(&DoReplay); }
};
ReplayInstallOnLoad g_replayInstallOnLoad;

// Slot installation table.
struct SlotInstall {
    int   slot;
    void* fn;
    const char* name;
};

const SlotInstall g_table[] = {
    { kSlot_BeginScene,                 (void*)Mirror_BeginScene,                 "BeginScene" },
    { kSlot_EndScene,                   (void*)Mirror_EndScene,                   "EndScene" },
    { kSlot_Clear,                      (void*)Mirror_Clear,                      "Clear" },
    { kSlot_SetTransform,               (void*)Mirror_SetTransform,               "SetTransform" },
    { kSlot_SetViewport,                (void*)Mirror_SetViewport,                "SetViewport" },
    { kSlot_SetRenderState,             (void*)Mirror_SetRenderState,             "SetRenderState" },
    { kSlot_SetSamplerState,            (void*)Mirror_SetSamplerState,            "SetSamplerState" },
    { kSlot_SetTextureStageState,       (void*)Mirror_SetTextureStageState,       "SetTextureStageState" },
    { kSlot_SetTexture,                 (void*)Mirror_SetTexture,                 "SetTexture" },
    { kSlot_DrawPrimitive,              (void*)Mirror_DrawPrimitive,              "DrawPrimitive" },
    { kSlot_DrawIndexedPrimitive,       (void*)Mirror_DrawIndexedPrimitive,       "DrawIndexedPrimitive" },
    { kSlot_SetVertexShader,            (void*)Mirror_SetVertexShader,            "SetVertexShader" },
    { kSlot_SetVertexShaderConstantF,   (void*)Mirror_SetVertexShaderConstantF,   "SetVertexShaderConstantF" },
    { kSlot_SetPixelShader,             (void*)Mirror_SetPixelShader,             "SetPixelShader" },
    { kSlot_SetPixelShaderConstantF,    (void*)Mirror_SetPixelShaderConstantF,    "SetPixelShaderConstantF" },
    { kSlot_SetStreamSource,            (void*)Mirror_SetStreamSource,            "SetStreamSource" },
    { kSlot_SetStreamSourceFreq,        (void*)Mirror_SetStreamSourceFreq,        "SetStreamSourceFreq" },
    { kSlot_SetIndices,                 (void*)Mirror_SetIndices,                 "SetIndices" },
    { kSlot_SetVertexDeclaration,       (void*)Mirror_SetVertexDeclaration,       "SetVertexDeclaration" },
    { kSlot_CreateTexture,              (void*)Mirror_CreateTexture,              "CreateTexture" },
    { kSlot_CreateVertexBuffer,         (void*)Mirror_CreateVertexBuffer,         "CreateVertexBuffer" },
    { kSlot_CreateIndexBuffer,          (void*)Mirror_CreateIndexBuffer,          "CreateIndexBuffer" },
    { kSlot_CreateVertexShader,         (void*)Mirror_CreateVertexShader,         "CreateVertexShader" },
    { kSlot_CreatePixelShader,          (void*)Mirror_CreatePixelShader,          "CreatePixelShader" },
    { kSlot_SetRenderTarget,            (void*)Mirror_SetRenderTarget,            "SetRenderTarget" },
    { kSlot_SetDepthStencilSurface,     (void*)Mirror_SetDepthStencilSurface,     "SetDepthStencilSurface" },
    // Get* wrappers — read-only, capture caller retaddr only.
    { kSlot_GetRenderTarget,            (void*)Mirror_GetRenderTarget,            "GetRenderTarget" },
    { kSlot_GetDepthStencilSurface,     (void*)Mirror_GetDepthStencilSurface,     "GetDepthStencilSurface" },
    { kSlot_GetTransform,               (void*)Mirror_GetTransform,               "GetTransform" },
    { kSlot_GetViewport,                (void*)Mirror_GetViewport,                "GetViewport" },
    { kSlot_GetRenderState,             (void*)Mirror_GetRenderState,             "GetRenderState" },
    { kSlot_GetTexture,                 (void*)Mirror_GetTexture,                 "GetTexture" },
    { kSlot_GetTextureStageState,       (void*)Mirror_GetTextureStageState,       "GetTextureStageState" },
    { kSlot_GetSamplerState,            (void*)Mirror_GetSamplerState,            "GetSamplerState" },
    { kSlot_GetVertexDeclaration,       (void*)Mirror_GetVertexDeclaration,       "GetVertexDeclaration" },
    { kSlot_GetVertexShader,            (void*)Mirror_GetVertexShader,            "GetVertexShader" },
    { kSlot_GetVertexShaderConstantF,   (void*)Mirror_GetVertexShaderConstantF,   "GetVertexShaderConstantF" },
    { kSlot_GetStreamSource,            (void*)Mirror_GetStreamSource,            "GetStreamSource" },
    { kSlot_GetIndices,                 (void*)Mirror_GetIndices,                 "GetIndices" },
    { kSlot_GetPixelShader,             (void*)Mirror_GetPixelShader,             "GetPixelShader" },
    { kSlot_GetPixelShaderConstantF,    (void*)Mirror_GetPixelShaderConstantF,    "GetPixelShaderConstantF" },
    // Stage 6: previously bypassed pipeline.
    { kSlot_DrawPrimitiveUP,            (void*)Mirror_DrawPrimitiveUP,            "DrawPrimitiveUP" },
    { kSlot_SetFVF,                     (void*)Mirror_SetFVF,                     "SetFVF" },
};

bool g_installed = false;
std::chrono::steady_clock::time_point g_lastLog;

}  // namespace

bool Install(IDirect3DDevice9* dev) {
    if (g_installed) return true;
    if (!dev) {
        OD_LOG("[MIRROR] Install: device is null");
        return false;
    }

    // Hand the device to the replay layer so the hot-sub thunks (NiDX9Hooks)
    // know which device to dispatch their replayed buffer through.
    overdrive::replay::SetDevice(dev);

    int ok = 0;
    for (const auto& e : g_table) {
        if (d3d9vt::ReplaceSlot(dev, e.slot, e.fn)) {
            ++ok;
        } else {
            OD_LOG("[MIRROR] Install: ReplaceSlot(%d=%s) failed", e.slot, e.name);
        }
    }

    g_installed = true;
    g_lastLog = std::chrono::steady_clock::now();
    OD_LOG("[MIRROR] Phase 6 typed wrappers installed: %d/%zu slots take the typed path. "
           "Remaining slots stay on counter thunks. Game still renders via real D3D9; "
           "mirror state catches up so future work can route to Vulkan instead.",
           ok, sizeof(g_table) / sizeof(g_table[0]));
    return ok > 0;
}

// Helper: format dedup as "skipped/(skipped+passed) = pct%"
static double DedupPct(uint64_t skipped, uint64_t passed) {
    const uint64_t total = skipped + passed;
    return total ? (100.0 * skipped / total) : 0.0;
}

void MaybeLogStats() {
    const auto now     = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog);
    if (elapsed.count() < 5000) return;
    g_lastLog = now;
    if (!g_installed) return;

    OD_LOG("[MIRROR] frames=%llu draws(P=%llu IP=%llu prims=%llu) state(RS=%llu Tex=%llu VS=%llu PS=%llu VSC=%llu PSC=%llu) "
           "binds(VB=%llu IB=%llu VP=%llu) "
           "resources(tex=%llu vb=%llu ib=%llu vs=%llu ps=%llu)",
           (unsigned long long)gStats.beginScene.load(std::memory_order_relaxed),
           (unsigned long long)gStats.drawPrimitive.load(std::memory_order_relaxed),
           (unsigned long long)gStats.drawIndexedPrimitive.load(std::memory_order_relaxed),
           (unsigned long long)gStats.totalPrimitives.load(std::memory_order_relaxed),
           (unsigned long long)gStats.setRenderState.load(std::memory_order_relaxed),
           (unsigned long long)gStats.setTexture.load(std::memory_order_relaxed),
           (unsigned long long)gStats.setVertexShader.load(std::memory_order_relaxed),
           (unsigned long long)gStats.setPixelShader.load(std::memory_order_relaxed),
           (unsigned long long)gStats.setVertexShaderConstantF.load(std::memory_order_relaxed),
           (unsigned long long)gStats.setPixelShaderConstantF.load(std::memory_order_relaxed),
           (unsigned long long)gStats.setStreamSource.load(std::memory_order_relaxed),
           (unsigned long long)gStats.setIndices.load(std::memory_order_relaxed),
           (unsigned long long)gStats.setViewport.load(std::memory_order_relaxed),
           (unsigned long long)gResources.textures.load(std::memory_order_relaxed),
           (unsigned long long)gResources.vertexBuffers.load(std::memory_order_relaxed),
           (unsigned long long)gResources.indexBuffers.load(std::memory_order_relaxed),
           (unsigned long long)gResources.vertexShaders.load(std::memory_order_relaxed),
           (unsigned long long)gResources.pixelShaders.load(std::memory_order_relaxed));

    // Dedup hit-rate summary — the actual perf-relevant numbers.
    const uint64_t ssSkipped = gStats.dedupSkipped_SamplerState.load(std::memory_order_relaxed);
    const uint64_t ssPassed  = gStats.dedupPassed_SamplerState.load(std::memory_order_relaxed);
    const uint64_t tssSkipped = gStats.dedupSkipped_TextureStageState.load(std::memory_order_relaxed);
    const uint64_t tssPassed  = gStats.dedupPassed_TextureStageState.load(std::memory_order_relaxed);
    const uint64_t rsSkipped = gStats.dedupSkipped_RenderState.load(std::memory_order_relaxed);
    const uint64_t rsPassed  = gStats.dedupPassed_RenderState.load(std::memory_order_relaxed);
    const uint64_t txSkipped = gStats.dedupSkipped_Texture.load(std::memory_order_relaxed);
    const uint64_t txPassed  = gStats.dedupPassed_Texture.load(std::memory_order_relaxed);
    const uint64_t vsSkipped = gStats.dedupSkipped_VertexShader.load(std::memory_order_relaxed);
    const uint64_t vsPassed  = gStats.dedupPassed_VertexShader.load(std::memory_order_relaxed);
    const uint64_t psSkipped = gStats.dedupSkipped_PixelShader.load(std::memory_order_relaxed);
    const uint64_t psPassed  = gStats.dedupPassed_PixelShader.load(std::memory_order_relaxed);
    const uint64_t streamSkipped = gStats.dedupSkipped_StreamSource.load(std::memory_order_relaxed);
    const uint64_t streamPassed  = gStats.dedupPassed_StreamSource.load(std::memory_order_relaxed);
    const uint64_t freqSkipped = gStats.dedupSkipped_StreamSourceFreq.load(std::memory_order_relaxed);
    const uint64_t freqPassed  = gStats.dedupPassed_StreamSourceFreq.load(std::memory_order_relaxed);
    const uint64_t idxSkipped = gStats.dedupSkipped_Indices.load(std::memory_order_relaxed);
    const uint64_t idxPassed  = gStats.dedupPassed_Indices.load(std::memory_order_relaxed);
    const uint64_t declSkipped = gStats.dedupSkipped_VertexDeclaration.load(std::memory_order_relaxed);
    const uint64_t declPassed  = gStats.dedupPassed_VertexDeclaration.load(std::memory_order_relaxed);
    const uint64_t xfSkipped = gStats.dedupSkipped_Transform.load(std::memory_order_relaxed);
    const uint64_t xfPassed  = gStats.dedupPassed_Transform.load(std::memory_order_relaxed);
    const uint64_t vpSkipped = gStats.dedupSkipped_Viewport.load(std::memory_order_relaxed);
    const uint64_t vpPassed  = gStats.dedupPassed_Viewport.load(std::memory_order_relaxed);
    const uint64_t vscSkipped = gStats.dedupSkipped_VSConstantF.load(std::memory_order_relaxed);
    const uint64_t vscTrimmed = gStats.dedupTrimmed_VSConstantF.load(std::memory_order_relaxed);
    const uint64_t vscPassed  = gStats.dedupPassed_VSConstantF.load(std::memory_order_relaxed);
    const uint64_t pscSkipped = gStats.dedupSkipped_PSConstantF.load(std::memory_order_relaxed);
    const uint64_t pscTrimmed = gStats.dedupTrimmed_PSConstantF.load(std::memory_order_relaxed);
    const uint64_t pscPassed  = gStats.dedupPassed_PSConstantF.load(std::memory_order_relaxed);

    const uint64_t totalSkipped = ssSkipped + tssSkipped + rsSkipped + txSkipped + vsSkipped + psSkipped
                                + streamSkipped + freqSkipped + idxSkipped + declSkipped
                                + xfSkipped + vpSkipped + vscSkipped + pscSkipped;
    const uint64_t totalPassed  = ssPassed  + tssPassed  + rsPassed  + txPassed  + vsPassed  + psPassed
                                + streamPassed + freqPassed + idxPassed + declPassed
                                + xfPassed + vpPassed + vscPassed + pscPassed;

    OD_LOG("[DEDUP] cumulative skipped %llu / passed %llu (overall %.1f%% eliminated)",
        (unsigned long long)totalSkipped, (unsigned long long)totalPassed,
        DedupPct(totalSkipped, totalPassed));
    OD_LOG("[DEDUP]  state:    SS %.1f%% (%llu/%llu) | TSS %.1f%% (%llu/%llu) | RS %.1f%% (%llu/%llu)",
        DedupPct(ssSkipped,  ssPassed),  (unsigned long long)ssSkipped,  (unsigned long long)ssPassed,
        DedupPct(tssSkipped, tssPassed), (unsigned long long)tssSkipped, (unsigned long long)tssPassed,
        DedupPct(rsSkipped,  rsPassed),  (unsigned long long)rsSkipped,  (unsigned long long)rsPassed);
    OD_LOG("[DEDUP]  binds:    Tex %.1f%% (%llu/%llu) | VS %.1f%% (%llu/%llu) | PS %.1f%% (%llu/%llu) | Decl %.1f%% (%llu/%llu)",
        DedupPct(txSkipped,  txPassed),  (unsigned long long)txSkipped,  (unsigned long long)txPassed,
        DedupPct(vsSkipped,  vsPassed),  (unsigned long long)vsSkipped,  (unsigned long long)vsPassed,
        DedupPct(psSkipped,  psPassed),  (unsigned long long)psSkipped,  (unsigned long long)psPassed,
        DedupPct(declSkipped, declPassed), (unsigned long long)declSkipped, (unsigned long long)declPassed);
    OD_LOG("[DEDUP]  geom:     Stream %.1f%% (%llu/%llu) | Freq %.1f%% (%llu/%llu) | Idx %.1f%% (%llu/%llu) | Xform %.1f%% (%llu/%llu) | Vp %.1f%% (%llu/%llu)",
        DedupPct(streamSkipped, streamPassed), (unsigned long long)streamSkipped, (unsigned long long)streamPassed,
        DedupPct(freqSkipped, freqPassed),     (unsigned long long)freqSkipped,   (unsigned long long)freqPassed,
        DedupPct(idxSkipped, idxPassed),       (unsigned long long)idxSkipped,    (unsigned long long)idxPassed,
        DedupPct(xfSkipped, xfPassed),         (unsigned long long)xfSkipped,     (unsigned long long)xfPassed,
        DedupPct(vpSkipped, vpPassed),         (unsigned long long)vpSkipped,     (unsigned long long)vpPassed);
    OD_LOG("[DEDUP]  consts:   VSConstF skipped=%llu trimmed=%llu passed=%llu (%.1f%% eliminated, %.1f%% trimmed) | PSConstF skipped=%llu trimmed=%llu passed=%llu (%.1f%% eliminated, %.1f%% trimmed)",
        (unsigned long long)vscSkipped, (unsigned long long)vscTrimmed, (unsigned long long)vscPassed,
        DedupPct(vscSkipped, vscTrimmed + vscPassed),
        (vscSkipped + vscTrimmed + vscPassed) ? (100.0 * vscTrimmed / (vscSkipped + vscTrimmed + vscPassed)) : 0.0,
        (unsigned long long)pscSkipped, (unsigned long long)pscTrimmed, (unsigned long long)pscPassed,
        DedupPct(pscSkipped, pscTrimmed + pscPassed),
        (pscSkipped + pscTrimmed + pscPassed) ? (100.0 * pscTrimmed / (pscSkipped + pscTrimmed + pscPassed)) : 0.0);
}

}  // namespace overdrive::mirror
