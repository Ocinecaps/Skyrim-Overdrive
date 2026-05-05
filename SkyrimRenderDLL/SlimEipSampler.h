#pragma once

// =============================================================================
// SlimEipSampler — render-thread CPU heatmap for the slim DLL
// =============================================================================
//
// Where is the render thread spending CPU time? That's the question we need
// to answer before we can pick a candidate for the idle-worker initiative.
// (We have a fancier multi-thread sampler in ScenegraphProfiler.cpp but it
// pulls in nidx9/d3d9hook/dbghelp/symbol-table dependencies that the slim
// DLL doesn't compile. This is the slimmest possible version — single
// thread, single histogram, no symbol resolution.)
//
// How it works:
//   1. A low-priority background thread waits for D3DXReplace to latch the
//      render TID (happens on the first D3DX call after game start).
//   2. Every 10ms (~100 Hz) it SuspendThread + GetThreadContext + ResumeThread
//      on the render thread, reads EIP, and bumps a 4 KB-page-bucketed
//      histogram. ~100 ms total suspend overhead per second of game time.
//   3. Every 30 seconds it logs the top 20 hottest pages with their hit
//      counts and percentages.
//
// To use the data: each `page=0x00CXXXXX` line is the 4 KB code region most
// recently sampled. Open IDA at the page base ± 0x1000 — if a single
// per-frame loop dominates, it'll be the function whose body covers that
// page. That's our idle-work candidate.

namespace overdrive::slimeip {

bool Install();
void Shutdown();
void MaybeLogStats();   // called from the worker pump; no-op (this module
                        // owns its own thread and dump cadence)

}
