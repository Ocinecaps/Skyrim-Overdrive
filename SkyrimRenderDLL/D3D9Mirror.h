#pragma once

#include <atomic>
#include <cstdint>
#include <vector>

struct IDirect3DDevice9;
struct IDirect3DTexture9;
struct IDirect3DVertexBuffer9;
struct IDirect3DIndexBuffer9;

namespace overdrive::mirror {

// Phase 6 — D3D9-to-Vulkan mirror.
//
// Goal: replace the entire rendering system with SDL3+Vulkan, incrementally.
//
// Architecture:
//   1. Phase 5 bulk-hooked all 119 IDirect3DDevice9 vtable slots with generic
//      counter thunks. Skyrim still renders via the real D3D9.
//   2. Phase 6 (this module) replaces SELECTED vtable slots with TYPED C++
//      wrappers. Each wrapper:
//        a) Updates the Vulkan-side mirror state (tracked here)
//        b) Calls the original D3D9 method via gOriginals[slot]
//        c) Returns the original's result
//      So Skyrim still renders correctly while our Vulkan-side state catches
//      up to know "what would the renderer be doing if it were Vulkan".
//   3. Future phases progressively replace each method's body so it does
//      Vulkan work instead of (or in addition to) the D3D9 call. Eventually
//      the D3D9 calls become no-ops and Skyrim renders entirely via Vulkan.
//
// This call is idempotent and safe to call multiple times.
// Returns true if the typed wrappers were installed.
bool Install(IDirect3DDevice9* dev);

// Periodic stats logger — counts of state changes, draws, resources created.
// Throttled internally to once per 5s.
void MaybeLogStats();

// Aggregate stats readable by HUD/external code.
//
// 32-bit (not 64-bit) on purpose. On x86-32, std::atomic<uint64_t>::fetch_add
// compiles to a LOCK CMPXCHG8B loop — ~50 cycles per increment, dominated by
// cache-line locking. atomic<uint32_t>::fetch_add is a single LOCK XADD,
// ~10 cycles. Profiling on 2026-05-03 showed atomic uint64 ops were 8.7% of
// our render-thread CPU. Per-second deltas (the only thing we display)
// remain correct under uint32 wraparound because (current - last_snap) in
// unsigned arithmetic is wrap-safe.
struct Stats {
    std::atomic<uint32_t> beginScene{0};
    std::atomic<uint32_t> endScene{0};
    std::atomic<uint32_t> clear{0};
    std::atomic<uint32_t> drawPrimitive{0};
    std::atomic<uint32_t> drawIndexedPrimitive{0};
    std::atomic<uint32_t> setRenderState{0};
    std::atomic<uint32_t> setTexture{0};
    std::atomic<uint32_t> setVertexShader{0};
    std::atomic<uint32_t> setPixelShader{0};
    std::atomic<uint32_t> setVertexShaderConstantF{0};
    std::atomic<uint32_t> setPixelShaderConstantF{0};
    std::atomic<uint32_t> setStreamSource{0};
    std::atomic<uint32_t> setIndices{0};
    std::atomic<uint32_t> setTransform{0};
    std::atomic<uint32_t> setViewport{0};
    std::atomic<uint32_t> createTexture{0};
    std::atomic<uint32_t> createVertexBuffer{0};
    std::atomic<uint32_t> createIndexBuffer{0};
    std::atomic<uint32_t> createVertexShader{0};
    std::atomic<uint32_t> createPixelShader{0};

    // Cumulative geometry: total primitives drawn this session.
    std::atomic<uint32_t> totalPrimitives{0};

    // Hot dedup counters — added in the redundant-call elimination pass.
    // Counts of calls SKIPPED because they would have set state to its
    // current value. These are direct CPU savings: each skip is one less
    // D3D9 driver thunk + one less command queue insertion.
    std::atomic<uint32_t> dedupSkipped_SamplerState{0};
    std::atomic<uint32_t> dedupSkipped_TextureStageState{0};
    std::atomic<uint32_t> dedupSkipped_RenderState{0};
    std::atomic<uint32_t> dedupSkipped_Texture{0};
    std::atomic<uint32_t> dedupSkipped_VertexShader{0};
    std::atomic<uint32_t> dedupSkipped_PixelShader{0};
    std::atomic<uint32_t> dedupSkipped_StreamSource{0};
    std::atomic<uint32_t> dedupSkipped_StreamSourceFreq{0};
    std::atomic<uint32_t> dedupSkipped_Indices{0};
    std::atomic<uint32_t> dedupSkipped_VertexDeclaration{0};
    std::atomic<uint32_t> dedupSkipped_Transform{0};
    std::atomic<uint32_t> dedupSkipped_Viewport{0};
    // Shader constant dedup is more nuanced: a SET call may be skipped
    // entirely (no register changed) OR trimmed (only a sub-range of
    // registers actually changed → forward a smaller call to D3D9).
    std::atomic<uint32_t> dedupSkipped_VSConstantF{0};
    std::atomic<uint32_t> dedupTrimmed_VSConstantF{0};
    std::atomic<uint32_t> dedupSkipped_PSConstantF{0};
    std::atomic<uint32_t> dedupTrimmed_PSConstantF{0};

    // Calls that DID make it through to D3D9 (after dedup).
    std::atomic<uint32_t> dedupPassed_SamplerState{0};
    std::atomic<uint32_t> dedupPassed_TextureStageState{0};
    std::atomic<uint32_t> dedupPassed_RenderState{0};
    std::atomic<uint32_t> dedupPassed_Texture{0};
    std::atomic<uint32_t> dedupPassed_VertexShader{0};
    std::atomic<uint32_t> dedupPassed_PixelShader{0};
    std::atomic<uint32_t> dedupPassed_StreamSource{0};
    std::atomic<uint32_t> dedupPassed_StreamSourceFreq{0};
    std::atomic<uint32_t> dedupPassed_Indices{0};
    std::atomic<uint32_t> dedupPassed_VertexDeclaration{0};
    std::atomic<uint32_t> dedupPassed_Transform{0};
    std::atomic<uint32_t> dedupPassed_Viewport{0};
    std::atomic<uint32_t> dedupPassed_VSConstantF{0};
    std::atomic<uint32_t> dedupPassed_PSConstantF{0};
};
extern Stats gStats;

// Resource registry — tracks every D3D9 resource Skyrim creates so we can
// later create matching Vulkan resources. For Phase 6 we just count and log;
// the Vulkan-side allocator comes in Phase 6.1.
struct ResourceTotals {
    std::atomic<uint32_t> textures{0};
    std::atomic<uint32_t> vertexBuffers{0};
    std::atomic<uint32_t> indexBuffers{0};
    std::atomic<uint32_t> vertexShaders{0};
    std::atomic<uint32_t> pixelShaders{0};
};
extern ResourceTotals gResources;

}
