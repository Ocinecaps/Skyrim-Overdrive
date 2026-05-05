#pragma once

#include <cstdint>

namespace overdrive::nidx9 {

// Phase 3: install inline detours at known RVAs of Skyrim's high-traffic
// Gamebryo NiDX9 helper functions (identified by IDA cross-reference profile
// in C:\Users\nro\Documents\ida scripts and extracted\high_performance_subroutines.txt).
//
// The detours are signature-agnostic naked-asm thunks that:
//   1. push eax
//   2. lock inc dword ptr [counter]    (atomic; no spurious torn writes)
//   3. pop eax
//   4. jmp [trampoline]                 (continues into original function)
//
// Net effect on the game: ~5-10 ns of overhead per call. The function executes
// normally and returns to its original caller. The only observable change is
// the counter incrementing.
//
// Phase 3 is OBSERVABILITY ONLY — no behavior change. Phase 4 will use the
// data gathered here to choose which functions to actually replace.
//
// Returns true if at least one hook was installed; false if all 3 failed.
bool Install();

// Call from any thread (cheap; throttled internally to once per 5 seconds).
// Logs current counter values + per-second rates for the hooked functions.
void MaybeLogStats();

// Direct readers for HUD / external use.
extern volatile uint32_t g_count_CB7E80;
extern volatile uint32_t g_count_B06250;
extern volatile uint32_t g_count_CA2610;

// Latest thread ID observed entering each hot sub. Each thunk writes
// `fs:[0x24]` (TEB.ClientId.UniqueThread) here on every entry. The
// scenegraph profiler reads these to know which thread to suspend+sample,
// since Skyrim uses D3DCREATE_MULTITHREADED and the scenegraph walk does
// NOT necessarily run on the same thread that calls Present.
extern volatile uint32_t g_lastTid_CB7E80;
extern volatile uint32_t g_lastTid_B06250;
extern volatile uint32_t g_lastTid_CA2610;

}
