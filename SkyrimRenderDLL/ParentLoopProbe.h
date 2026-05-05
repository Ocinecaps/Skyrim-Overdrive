#pragma once
#include <cstdint>

// =============================================================================
// ParentLoopProbe — find the per-frame loop that drives sub_CB1480 calls
// =============================================================================
//
// What we know from the D3DX caller histogram (slim DLL, 110s session):
//   - sub_CB7E80 is the dominant caller of D3DXMatrixMultiplyTranspose (71%)
//   - sub_CB7E80 is dispatched from sub_CB1480 via vtable[23] (parent loop
//     analysis — 95.75% of hot-sub outer entries)
//   - sub_CB1480 is wrapped by sub_CB1FF0 (scalar deleting destructor pattern)
//   - sub_CB1FF0 is called via vtable[0] dispatch from an UNKNOWN parent
//
// What we need: the unknown parent. It's the per-frame loop iterating over
// scenegraph nodes calling each one's vtable[0] (= sub_CB1FF0 for class C).
// That loop's iterations are independent (one node per iteration), making
// it the safe Phase 3 ParallelFor target.
//
// How we find it: hook sub_CB1FF0's entry. On every call, capture the return
// address (= the instruction right after the vtable[0] dispatch in the
// parent loop). After enough samples, the dominant retaddr is the parent.
//
// We ALSO hook sub_CB1480 directly as a backup signal — its retaddr should
// dominantly be 0x00CB1FF8 (inside sub_CB1FF0+0x3), which we already know,
// but verifying keeps the chain consistent. Both probes log periodically.

namespace overdrive::parentloop {

// Install MinHook detours on sub_CB1FF0 (scalar deleting destructor) and
// sub_CB1480 (destructor body / render-prep dispatcher). Both are at
// fixed VAs in TESV.exe.
bool Install();

void Shutdown();

// Periodic dump of parent retaddr histograms for both functions.
// Throttled internally to once per 10 seconds.
void MaybeLogStats();

}
