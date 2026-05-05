#pragma once
#include <cstdint>

// =============================================================================
// RenderPoolPatch — feed Skyrim's own 6-worker thread pool from the outside
// =============================================================================
//
// THIS IS THE SHIPPABLE-MOD MODULE. Skyrim allocates a generic 6-worker thread
// pool at sub_A5B050, used internally for non-render CPU work. The wait
// profiler shows its dispatcher (sub_A5AC30) sitting INFINITE on a semaphore
// at ~33-75% of all TESV WaitForSingleObject calls — workers are mostly idle.
//
// Render-prep work on the render thread (matrix transforms, visibility cull,
// drawcall-list building) runs sequentially even though those iterations are
// independent. By submitting that prep work as tasks to Skyrim's existing
// pool, six cores grind through it in parallel while the render thread is
// busy elsewhere — the actual multi-core rendering win.
//
// =============================================================================
// Task ABI — fully decoded from sub_A5AE90 (worker dispatch loop) disassembly
// =============================================================================
//
// Worker pseudo-code (from disasm at 0x00A5AE90..0x00A5AFC1):
//
//   for (;;) {
//       WaitForSingleObject(pool.masterSem[+0x26C], INFINITE);
//       if (pool.shutdown[+0x50]) break;
//       EnterCriticalSection(&pool.cs[+0x54]);
//         // Scan slots [+0x6C..+0x6C + 64*4] for a non-null head
//         for (i = 0; i < 64; ++i) {
//             task = pool.queue[i];
//             if (task) {
//                 pool.queue[i] = task->next;   // task->[+0x14] = next-in-bucket
//                 group = task->group;          // task->[+0x08]
//                 break;
//             }
//         }
//       LeaveCriticalSection(&pool.cs[+0x54]);
//
//       if (!task || !group) continue;
//
//       // arg_0 / re-queue logic — task->[+0x4] becomes 1 if caller's arg_0
//       // matches a particular group filter. Not relevant for our submission
//       // path; we set task->[+0x4] = 0.
//
//       if (group->[+0x26] == 0 && task->[+0x0C] == 0) {
//           // optional pre-Run check
//           if (!task->vtable[1](task)) goto skip_run;
//       }
//       task->vtable[2](task);                  // === RUN ===
//       task->[+0x0C] = 0;
//
//   skip_run:
//       if (task->[+0x4] != 0 && group->[+0x26] == 0) {
//           // re-queue path — taken when caller's arg_0 matched (we don't use)
//           sub_A5AD60(pool, task);
//           continue;
//       }
//
//       task->vtable[3](task);                  // === FINISH ===
//       task->[+0x08] = 0;
//       task->[+0x10] = 0;
//
//       EnterCriticalSection(&group->cs[+0x0C]);
//         group->counter[+0x30]++;
//         release = (group->[+0x25] == 0 && group->counter == group->target[+0x2C]);
//       LeaveCriticalSection(&group->cs[+0x0C]);
//       if (release) ReleaseSemaphore(group->sem[+0x8], 1, NULL);
//   }
//
// =============================================================================
// OdTask / OdTaskGroup struct layouts (binary-compatible with Skyrim tasks)
// =============================================================================
//
//   OdTask (size = 0x18+ minimum)
//     +0x00  void**           vtable;        // points at OdTaskVtable
//     +0x04  uint8_t          requeueFlag;   // set to 1 if worker should re-queue post-Run
//     +0x05..0x07  padding
//     +0x08  OdTaskGroup*     group;         // group this task belongs to
//     +0x0C  uint8_t          skipValidate;  // when 0, vtable[1] called as gate before Run
//     +0x0D..0x0F  padding
//     +0x10  void*            field10;       // cleared at Finish — caller may use as scratch
//     +0x14  OdTask*          next;          // intra-slot linked list
//
//   OdTaskVtable (4 entries, 0x10 bytes)
//     [0]  void  __thiscall (*dtor)(OdTask*)
//     [1]  bool  __thiscall (*Validate)(OdTask*)   // optional, return true to allow Run
//     [2]  void  __thiscall (*Run)(OdTask*)        // === the work ===
//     [3]  void  __thiscall (*Finish)(OdTask*)     // post-Run cleanup
//
//   OdTaskGroup (size 0x40+ minimum — full layout TBD)
//     +0x00  void*            vtable;
//     +0x08  HANDLE           sem;          // released when group completes
//     +0x0C  CRITICAL_SECTION cs;           // protects counter
//     +0x25  uint8_t          flag25;       // when nonzero, completion suppressed
//     +0x26  uint8_t          flag26;       // when nonzero, the per-task gate at AF39 is skipped
//     +0x2C  uint32_t         target;       // expected #completions to release sem
//     +0x30  uint32_t         counter;      // current completion count
//
// =============================================================================
// Pool struct layout (verified from IDA disasm of sub_A5B050)
// =============================================================================
//
//   +0x000  vtable*           (initially 0x0110DC44, then 0x0110DD1C after init)
//   +0x008  HANDLE workerSem  (worker wake semaphore — supervisor signals here)
//   +0x00C  LONG taskCounter  (InterlockedDecrement during dispatch)
//   +0x018  uint32_t workerCount  (= 6, the cap)
//   +0x01C  uint32_t threadCount
//   +0x020  HANDLE threadHandles[]  (worker thread handles, count at +0x1C)
//   +0x050  uint8_t  shutdownFlag
//   +0x054  CRITICAL_SECTION cs   (locks the task queue)
//   +0x06C  OdTask*  taskQueue[64]  (64 slots × 4 bytes — head of intra-slot linked list)
//   +0x26C  HANDLE masterSem    (released to wake workers on enqueue)
//
// =============================================================================
// Capture strategy (this iteration: hook + memory-scan fallback)
// =============================================================================
//
//   1) Install MH hook on sub_A5B050 ASAP from the bootstrap worker (BEFORE
//      any other instrumentation install) — gives us the best chance of
//      catching the ctor.
//
//   2) If the hook misses (Skyrim already constructed the pool before our DLL
//      finished injecting), fall back to memory-scanning the process address
//      space for an object whose vtable matches 0x0110DD1C and whose worker-
//      count field at +0x18 equals 6. Singleton — exactly one such object.
//
// =============================================================================

namespace overdrive::renderpool {

// Install the hook on sub_A5B050. Returns false if MinHook initialization or
// hook installation fails. Idempotent — second call is a no-op.
//
// Call this AS EARLY AS POSSIBLE in the bootstrap worker thread to maximize
// the chance of catching the pool ctor. If the hook misses (sub_A59930
// already ran during TESV's pre-DLL init), MaybeLogStats will fall back to
// memory-scanning to find the live pool.
bool Install();

// Shut down: disable hook, drop captured pool pointer.
void Shutdown();

// Periodic pump. Called from the BootstrapThread instrumentation loop (~4 Hz):
//   - Pumps the passive task-queue observer (logs unique task vtables)
//   - Verifies the captured pool's vtable matches expectations
//   - If pool not yet captured after warmup, kicks off memory-scan fallback
//   - Throttles a stats log line to once per 5s.
void MaybeLogStats();

// Diagnostic accessor — the captured pool pointer. nullptr until either the
// hook fires OR memory-scan finds it.
void* GetPool();

// Suppress the periodic 5-second log line from MaybeLogStats. Self-test and
// scaling-test logs still emit (they're one-shot). Used by the slim DLL
// build to remove the only remaining repetitive log noise so vanilla-vs-
// modded FPS comparisons are clean.
void SetQuietMode(bool quiet);

// =============================================================================
// Phase 2: parallel-fork API — Skyrim's worker pool from the outside
// =============================================================================
//
// Run `numTasks` instances of `fn` in parallel on Skyrim's own 6 worker
// threads, then return when ALL have completed. Synchronization piggybacks
// on the pool's existing per-task-group semaphore: when our last task's
// Finish runs, the worker increments group->counter to == target and
// releases group->sem; the calling thread wakes from WaitForSingleObject.
//
// `fn(taskIdx, userData)` may run on any worker. taskIdx ranges 0..numTasks-1
// uniquely (each task gets a distinct index). userData is passed verbatim.
//
// Returns true if all tasks completed; false if pool isn't captured yet or
// numTasks == 0. Caller must keep userData valid for the duration of the
// call (we block until all tasks finish, so a stack-allocated struct works).
//
// SAFETY: fn must NOT call D3D9 (the workers don't hold the d3d9 driver lock
// in any predictable way). Pure CPU work only — math, memory copies, BVH
// updates, etc. fn must be reentrant — the same pointer can be called from
// multiple threads simultaneously with different taskIdx.
bool RunParallel(uint32_t numTasks,
                 void (*fn)(uint32_t taskIdx, void* userData),
                 void* userData);

// =============================================================================
// ParallelFor — divide [start, end) across workers, each gets a chunk
// =============================================================================
//
// The standard parallel-loop primitive. Internally splits the range into
// numTasks chunks (default = 6, matching Skyrim's pool worker count) and
// dispatches each chunk to a worker via RunParallel. Body is called once
// per index in [start, end).
//
//   ParallelFor(0, numObjects, [](uint32_t i, void*){ updateObject(i); }, nullptr);
//
// SAFETY: same constraints as RunParallel — body must NOT call D3D9, must
// be reentrant, and iterations must be independent (no cross-iteration
// data dependencies). This is the standard "embarrassingly parallel"
// pattern that fits matrix transforms, visibility cull per-cell, light
// list construction, particle update, etc.
//
// Returns true if all chunks completed; false if pool unavailable.
bool ParallelFor(uint32_t start, uint32_t end,
                 void (*body)(uint32_t i, void* userData),
                 void* userData);

}
