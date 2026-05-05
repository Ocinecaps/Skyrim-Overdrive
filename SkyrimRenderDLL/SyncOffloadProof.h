#pragma once

// =============================================================================
// SyncOffloadProof — prove that real Skyrim render-prep work can run on
// a pool worker thread instead of the main render thread.
// =============================================================================
//
// Hooks sub_CB7E80 (the dominant per-object matrix-prep function — 50% of
// D3DXMatrixMultiplyTranspose calls return into it). A configurable fraction
// (1-in-N, default N=1000) of invocations is rerouted onto Skyrim's own
// 6-worker pool with a synchronous wait. The remaining calls run inline on
// the render thread as usual.
//
// Why 1-in-N first: the first time we run game code on a pool worker, that
// worker's TLS slot has whatever the worker init wrote there — NOT what the
// render thread set up before calling sub_CB7E80 (sub_CAFDF0 sets a TLS
// allocator-group at +0x4AC). Rare offloads make any TLS-divergence bug
// recoverable. If 1-in-1000 is stable, ratchet via SetOneInN(): 1000 → 100
// → 10 → 1 (full offload).
//
// Stable end-state with N=1: every per-object render-prep call runs on a
// worker thread. Multi-core drawcalling proven on real Skyrim state. The
// sync wait means perf is not improved (each call still serialized through
// the wait), but the *threading model* is multi-core. Real perf gain comes
// in the next phase: hook the parent loop and run iterations in parallel.

namespace overdrive::syncproof {

bool Install();
void Shutdown();

// Adjust the 1-in-N ratio at runtime. n=1 means every call is offloaded.
// n>=1 required; values <1 are clamped to 1.
void SetOneInN(int n);

// Periodic stats — called from the worker pump (~4 Hz). Logs every 5s:
//   [SyncProof] sub_CB7E80: total=N offloaded=M workerExec=K
//                renderTid=R workerTids=[T1,T2,...]
// If renderTid != any workerTid, multi-core IS happening on Skyrim's own work.
void MaybeLogStats();

}
