#pragma once
#include <cstdint>

namespace overdrive::vkq {

// =============================================================================
// VulkanCommandQueue — scaffolding for the eventual D3D9 → Vulkan path
// =============================================================================
//
// True multi-core rendering requires recording commands on multiple threads
// and submitting them as command buffers. D3D9 doesn't support that; Vulkan
// does. This module is the FOUNDATION for that future path.
//
// What it does today (v1, scaffolding only):
//   - Defines a compact `Cmd` struct (op + 4 uint32 args) representing a
//     D3D9 call we'd want to translate.
//   - Owns a single-producer/single-consumer ring buffer (lock-free push,
//     lock-free pop).
//   - Spawns one drain thread that pops cmds and counts them (no actual
//     translation yet).
//   - Reports periodic stats: throughput, queue depth, drain lag.
//
// What it will become (v2+, real Vulkan submission):
//   - Drain thread translates each Cmd to its Vulkan equivalent and records
//     into a `VkCommandBuffer`.
//   - Render thread submits the command buffer to a `VkQueue`.
//   - Eventually: producer side fans out to MULTIPLE producers (multi-thread
//     command recording, the actual goal of "multi-core rendering").
//
// Why now: the queue+drain pattern, sized correctly, is the single most
// important architectural choice for the Vulkan path. Building it as a stub
// today gives us throughput numbers + lets the Mirror wrappers practice
// pushing without committing to anything. If the queue can sustain Skyrim's
// peak rate without backpressure, we know the architecture is viable.
//
// The push side adds ~3 ns per call (one atomic store + one indexed write).
// That's effectively free compared to the D3D9 call we're shadowing.

enum CmdOp : uint8_t {
    CMD_NONE = 0,
    CMD_SET_RENDER_STATE,        // args: state, value
    CMD_SET_TEXTURE,             // args: stage, textureHandle
    CMD_SET_VERTEX_SHADER,       // args: shaderHandle
    CMD_SET_PIXEL_SHADER,        // args: shaderHandle
    CMD_SET_VS_CONSTANT_F,       // args: startReg, vec4Count, dataHandle
    CMD_SET_PS_CONSTANT_F,       // args: startReg, vec4Count, dataHandle
    CMD_SET_STREAM_SOURCE,       // args: streamN, vbHandle, offset, stride
    CMD_SET_INDICES,             // args: ibHandle
    CMD_DRAW_PRIMITIVE,          // args: primType, startVtx, primCount
    CMD_DRAW_INDEXED_PRIMITIVE,  // args: primType, baseVtx, minVtx, vtxCount
    CMD_BEGIN_SCENE,
    CMD_END_SCENE,
    CMD_CLEAR,                   // args: count, flags, color, z
    CMD_COUNT_                   // sentinel
};

struct Cmd {
    uint8_t  op;
    uint8_t  pad[3];
    uint32_t args[4];
};

// Install the queue + spawn the drain thread. Idempotent.
bool Install();

// Periodic logger — throughput, queue depth, drain lag. Call from worker.
// Throttled internally (5s).
void MaybeLogStats();

void Shutdown();

// Push a command from the producer (D3D9Mirror wrapper). Lock-free, ~3ns
// in the no-contention case. Returns false if the queue is full (caller
// can either drop the cmd, spin briefly, or sync-flush — for v1 we just
// drop and bump a counter).
//
// Phase B (multi-producer): each calling thread automatically claims a
// per-thread SPSC ring on first push (up to kMaxProducers slots). Push is
// then completely contention-free — each producer writes to its own ring,
// the drain thread fans in. This is the architectural change that lets
// Skyrim's worker threads record draws in parallel without serializing
// through a global lock.
bool Push(const Cmd& c);

// Explicitly release the calling thread's producer slot. Optional — if a
// thread exits without releasing, the slot remains claimed (slots are sized
// for >> any expected producer count, so leaks are harmless). Useful for
// transient producers (synthetic tests, short-lived workers) that should
// give back their slot.
void ReleaseProducerSlot();

// Direct accessors for cheap inline use in Mirror wrappers — push without
// constructing a Cmd struct on the stack first.
bool PushOp1(uint8_t op, uint32_t a0);
bool PushOp2(uint8_t op, uint32_t a0, uint32_t a1);
bool PushOp3(uint8_t op, uint32_t a0, uint32_t a1, uint32_t a2);
bool PushOp4(uint8_t op, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3);

}
