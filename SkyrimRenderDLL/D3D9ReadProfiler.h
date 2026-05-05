#pragma once

#include <cstdint>

namespace overdrive::readprofiler {

// =============================================================================
// D3D9 read-site profiler
// =============================================================================
//
// Purpose: identify every TESV.exe call site that reads D3D9 state via Get*
// methods. These are the most likely glitch sources under the multi-core
// pipeline architecture, because Get* methods read REAL device state — which
// lags the queued (not-yet-dispatched) Set* operations.
//
// Concretely: if Skyrim does
//
//   IDirect3DSurface9* saved;
//   GetRenderTarget(0, &saved);   // reads stale value if SetRT is queued
//   SetRenderTarget(0, temp);     // queued
//   ... draws to temp ...         // queued
//   SetRenderTarget(0, saved);    // queued — but `saved` is wrong
//
// the "restore" goes to the wrong RT. Instrumenting Get* tells us WHERE in
// TESV.exe these patterns happen so we can target them.
//
// Each typed Mirror_Get* wrapper calls Note(slotId, retaddr). The retaddr is
// the TESV.exe instruction immediately after the vtable call (read via the
// _ReturnAddress() intrinsic). We bucket per-(slot, retaddr) pair and log
// the top callers per slot every 5 seconds, with TESV symbol resolution via
// crashdbg::ResolveTesvAddr (the IDA-extracted symbol table).

// Slot IDs — small numbers so we can use an array. Mirror the order with
// kSlotNames in D3D9ReadProfiler.cpp.
enum SlotId : uint32_t {
    READ_GetRenderTarget = 0,
    READ_GetDepthStencilSurface,
    READ_GetTransform,
    READ_GetRenderState,
    READ_GetTexture,
    READ_GetSamplerState,
    READ_GetTextureStageState,
    READ_GetVertexShader,
    READ_GetPixelShader,
    READ_GetStreamSource,
    READ_GetIndices,
    READ_GetVertexDeclaration,
    READ_GetVertexShaderConstantF,
    READ_GetPixelShaderConstantF,
    READ_GetViewport,
    READ_COUNT_,
};

// Called from each Mirror_Get* wrapper on every invocation.
void Note(SlotId slot, uint32_t retaddr);

// Periodic log line. Throttled to once per 5s.
void MaybeLogStats();

}
