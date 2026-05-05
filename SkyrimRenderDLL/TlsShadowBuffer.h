#pragma once

#include <cstdint>

// =============================================================================
// TlsShadowBuffer — per-thread shadow buffers for the scenegraph constants
// =============================================================================
//
// Goal: enable concurrent execution of sub_CB7E80 / sub_CA2610 (and their
// helpers) on multiple pool workers without racing on Skyrim's global
// vertex-shader constants buffers `dword_1BAC080` and `dword_1BAE0A8`.
//
// Strategy:
//   - Each worker thread owns its own shadow copy of both constants buffers.
//   - The TLS-shadowed *replacement* of sub_CB7E80 (forthcoming, in
//     ThreadSafeSceneprep.cpp) writes to its own shadow.
//   - After ParallelFor completes, the render thread serially merges each
//     worker's shadow back into the real globals in submission order, then
//     normal D3D9 drawcalls proceed.
//
// This module is the foundation only — it allocates and zeros the shadows
// and exposes accessors. The replacement function logic and the merge step
// live in their own modules.
//
// Indexed by an integer 0..kMaxShadowSlots-1, NOT by GetCurrentThreadId().
// Why: TIDs are not contiguous and would force a hashmap or an O(N) scan;
// we know the pool has at most 6 workers, plus the render thread and any
// transient hooks, so a fixed slot array indexed by an explicit "shadow
// slot ID" is faster and cache-friendly. Each worker claims its slot on
// first use (one-shot CAS).
//
// Size constants based on the max indices observed in the disasm:
//   dword_1BAC080: addressed up to [eax*4] where eax is a WORD (max 0xFFFF)
//                  but practical use is ~256 vec4 (4 KB). We allocate 4 KB.
//   dword_1BAE0A8: same shape, same allocation.
//
// Total memory: 8 KB per slot × 8 slots = 64 KB. Fits in cache, negligible.

namespace overdrive::tlsshadow {

constexpr int kMaxShadowSlots   = 8;
constexpr int kShadowBufferBytes = 4096;  // per buffer per thread

// Zero-init all shadows. Call once at install time.
void Init();

// Claim a shadow slot for the calling thread. Idempotent — returns the same
// slot index for the same thread on subsequent calls. Returns -1 if all
// slots are occupied (should not happen with kMaxShadowSlots = 8).
int ClaimSlot();

// Get the slot index this thread previously claimed, or -1 if none.
int GetSlot();

// Release this thread's slot. Call from worker thread on shutdown if needed
// (typically not necessary — slots persist until process exit).
void ReleaseSlot(int slot);

// Accessors. Pass an explicit slot (from ClaimSlot/GetSlot).
void* GetShadowBAC080(int slot);
void* GetShadowBAE0A8(int slot);

// After ParallelFor completes, the render thread calls this for each slot
// that was used in the burst, in queue-submission order. Copies the slot's
// shadow into the real dword_1BAC080 / dword_1BAE0A8 globals.
//
// `slotMask` is a bitmask of which slots participated. The render thread
// iterates set bits in queue order to drive merging.
//
// Note: only the SLOTS that wrote during the burst are merged. The replacement
// function logic must record which entries it actually touched (a bitmap or
// dirty-list per shadow), or this function copies the entire 4 KB. Initial
// version copies entire buffer for simplicity.
void MergeSlot(int slot,
               uint32_t realBac080VA,
               uint32_t realBae0a8VA);

}
