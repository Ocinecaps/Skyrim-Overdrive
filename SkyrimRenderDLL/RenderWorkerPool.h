#pragma once

#include <cstdint>
#include <functional>

struct IDirect3DDevice9;

namespace overdrive::workerpool {

// =============================================================================
// Week 3b — render worker pool
// =============================================================================
//
// Backing infrastructure for parallel scenegraph traversal. Workers pick up
// jobs that record D3D9 calls into their per-thread buffer (via the existing
// hot-sub thunks). After all jobs complete, the coordinator drains all
// per-worker buffers and replays them through D3D9 in submission order.
//
// Lifecycle per "parallel scope":
//
//   StartScope();
//   for (each scenegraph child) {
//       Submit([child] { child->vtable[25](child); });   // queues to worker
//   }
//   WaitAll();                  // blocks until all submitted jobs complete
//   DrainAndReplay(dev);        // replays buffers in submission order
//   EndScope();
//
// Dormant by default: until StartScope is called, no worker threads exist.
// First call lazily spawns the workers (Init() if not yet done).
//
// Each worker thread has:
//   - its own thread_local g_recording / g_buffer (existing replay layer)
//   - its own thread_local t_skipReplay = true (so ExitThunk_HotSub leaves
//     the buffer for the coordinator instead of replaying locally)
//   - a registered slot in g_workerBuffers so the coordinator can read its
//     buffer pointer for the drain pass
//
// Threading guarantees:
//   - Submit may be called only from the coordinator thread (single-producer)
//   - WaitAll, DrainAndReplay, StartScope, EndScope: coordinator thread only
//   - Worker threads only touch their own thread_local state + the job queue

constexpr int kMaxWorkers = 8;

// Initialize the pool. n = number of worker threads. Idempotent. Safe to skip
// (StartScope will lazy-init with a default count).
bool Init(int n);

// Marks the start of a parallel section. Resets submission index; clears
// outbox. Cheap (no thread sync). Must be paired with EndScope.
void StartScope();

// Mark the end of a parallel section. Lets the pool know it's safe to spin
// down idle workers if desired. (Currently a no-op; reserved.)
void EndScope();

// Submit a job. The worker that picks it up will:
//   - set t_skipReplay = true
//   - call StartRecording (via the hot-sub thunk's depth=0 entry)
//   - run fn()
//   - on hot-sub return, ExitThunk_HotSub sees t_skipReplay → does NOT replay
//   - move thread_local g_buffer into the outbox under the assigned index
//
// fn must call into Skyrim code that hits one of the hooked hot subs;
// otherwise the buffer will be empty and the drain will skip it.
//
// Returns the submission index (used internally to preserve replay order).
uint32_t Submit(std::function<void()> fn);

// Block until every submitted job has completed. Coordinator-thread only.
void WaitAll();

// Replay all worker buffers through orig<>() on `dev`, in submission-index
// order, then clears the outbox. Coordinator-thread only.
//
// Assumes WaitAll has already been called (or that no further Submits will
// happen). Passing a null device skips replay (used for shutdown drain).
void DrainAndReplay(IDirect3DDevice9* dev);

// Stats — for the periodic log line. Cumulative since pool init.
struct Stats {
    uint32_t scopesEntered;
    uint32_t jobsSubmitted;
    uint32_t jobsCompleted;
    uint32_t recordsReplayed;
    uint32_t outboxHighWater;   // peak outbox depth
};
Stats GetStats();

// Periodic log line. Throttled to 5s.
void MaybeLogStats();

}
