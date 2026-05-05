#pragma once

// =============================================================================
// BurstBatch — render-thread-only batched ParallelFor over hot per-object subs
// =============================================================================
//
// Replaces the SyncOffloadProof "submit-1-task-and-wait-per-call" pattern.
// That pattern was deadlock-prone: if the caller holds a critical section
// the worker also needs (save path, allocator path), main waits for worker
// while worker waits for main → freeze.
//
// New pattern:
//
//   hook sub_CB7E80 / sub_CA2610:
//     if currentThread != latched render thread → passthrough to original
//                                                 (deadlock-proof: any thread
//                                                 that might hold an inner-game
//                                                 lock just runs sequentially)
//     else:
//       push (tramp, this, arg) into render-thread-only queue
//       if queue size == K (=32):
//           renderpool::ParallelFor(0, K, body, queue) — fans out across the
//                                                       6 workers, render thread
//                                                       waits ONCE for the burst
//           queue clears
//       return — no wait per call
//
// Net: ~75 bursts/frame instead of 2400 sync-waits. The render thread's
// per-object work happens on the pool workers in parallel. Save and other
// non-render-thread paths run untouched.
//
// Independence assumption: the K calls in a burst execute concurrently, so
// per-object work must not write to shared mutable state across iterations.
// Standard scenegraph world-matrix pattern (each object writes its own slot)
// satisfies this. If we see flickering meshes, that assumption broke and we
// either lower K or special-case the offending object types.
//
// Drain on shutdown to flush leftover items.

namespace overdrive::burst {

bool Install();
void Shutdown();
void MaybeLogStats();

// Until SetEnabled(true), every hooked call passthroughs to the original
// without batching. This keeps the hooks installed-but-inert until the
// pool is confirmed dispatchable (e.g., scaling test passed). Avoids
// blocking on ParallelFor before workers are running.
void SetEnabled(bool enabled);

}
