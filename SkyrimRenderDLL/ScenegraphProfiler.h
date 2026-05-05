#pragma once

namespace overdrive::profiler {

// Stage-1 EIP-sampling profiler. A dedicated low-priority thread suspends the
// captured render thread at ~1 kHz, reads its EIP, buckets the sample into
// the three hot-sub address ranges (sub_CB7E80, sub_CA2610, sub_B06250).
// Output: every 5s, a log line showing the percentage of render-thread time
// observed inside each function.
//
// We deliberately do NOT bracket entry/exit with RDTSC. The hot subs are
// recursive __thiscall functions; making bracketing safe under recursion +
// the 32-bit thiscall ABI requires a per-thread shadow return-address stack
// + naked-asm exit handlers, which is a day of work to debug carefully.
// Sampling answers the same question ("is this >25% of frame time?") with
// no risk of corrupting Skyrim's stack.
//
// Returns true on successful thread launch.
bool Install();

// Joins the sampler thread. Safe to call multiple times.
void Shutdown();

// Throttled internally to once per 5s. Call from the worker loop.
void MaybeLogStats();

}
