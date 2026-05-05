#pragma once

#include <atomic>
#include <cstdint>

struct IDirect3DDevice9;

namespace overdrive::d3d9vt {

// Bulk-hook every single method of IDirect3DDevice9's vtable (all 119 slots
// in IUnknown + IDirect3DDevice9). Each hook is a 15-byte naked thunk that:
//   1. push eax
//   2. lock inc qword [counter_for_this_slot]
//   3. pop eax
//   4. jmp dword [original_for_this_slot]
//
// Effect: every single D3D9 device call from Skyrim — every state set, every
// resource bind, every draw call, every Reset/Release — increments a per-slot
// counter, then chains to the real implementation. Calling-convention
// agnostic (each slot has different args; the thunk doesn't touch them).
//
// Slot 17 (Present) is intentionally SKIPPED because D3D9Hook installs a
// specialized HookedPresent there for frame capture. Skipping avoids
// double-counting and keeps the capture path clean.
//
// Call AFTER the device pointer is captured (in HookedCreateDevice). Idempotent.
bool BulkHookDevice(IDirect3DDevice9* dev);

// Periodic stats logger — top-10 hottest slots by calls/sec, plus totals.
// Throttled internally to once per 5 seconds.
void MaybeLogStats();

// Number of vtable slots we track.
constexpr int kNumSlots = 119;

// Counter array (atomic, lock-free monotonic increment per slot).
//
// 32-bit on purpose: profiling on 2026-05-05 showed the render thread
// (T5728) spending 3.16% of CPU in std::_Atomic_integral<uint64_t,8>::fetch_add
// — overwhelmingly here, since every D3D9 method call increments one of these.
// On x86-32, atomic<uint64_t>::fetch_add is a LOCK CMPXCHG8B loop (~50 cyc);
// atomic<uint32_t>::fetch_add is a single LOCK XADD (~10 cyc). Per-second
// deltas are wrap-safe under unsigned subtraction so the log line is correct.
extern std::atomic<uint32_t> gCounters[kNumSlots];

// Human-readable slot names — indexed by vtable slot.
extern const char* kSlotNames[kNumSlots];

// Pre-bulk-hook function pointers — one per slot. After BulkHookDevice has
// run, slot N's vtable entry points to our generated thunk; the original
// function pointer is here. Phase 6 typed wrappers chain to these to forward
// calls to the real D3D9 implementation.
extern void* gOriginals[kNumSlots];

// Replace a single slot's vtable entry with a custom function pointer.
// Used by D3D9Mirror to install typed wrappers in place of generic counter
// thunks for methods we want to handle specially. Returns true on success.
// Idempotent / safe to call multiple times for the same slot.
bool ReplaceSlot(struct IDirect3DDevice9* dev, int slot, void* newFn);

}
