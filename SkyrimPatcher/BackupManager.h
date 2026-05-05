#pragma once

#include <string>

namespace patcher {

// Two backup files are maintained next to TESV.exe:
//
//   TESV.exe.original  — pristine bytes captured the very first time we ever
//                        touched this exe. NEVER overwritten after creation.
//                        Used by RestoreFromOriginal and as the diff baseline.
//
//   TESV.exe.previous  — snapshot of TESV.exe taken IMMEDIATELY before each
//                        new patch run. Overwritten every patch.
//                        Lets you undo the most recent patch even if you've
//                        modified the exe by hand since.
//
// EnsurePatchReadySource:
//   - On first ever run: capture TESV.exe -> TESV.exe.original.
//   - On every subsequent run:
//       a) Snapshot the current TESV.exe -> TESV.exe.previous (so you can
//          undo this patch attempt later).
//       b) Restore TESV.exe from TESV.exe.original (so we always patch
//          against pristine bytes — idempotent re-patching).
//   Returns true on success.
bool EnsurePatchReadySource(const std::string& exePath);

// Restore TESV.exe from TESV.exe.original. Returns false if .original missing.
bool RestoreFromOriginal(const std::string& exePath);

// Restore TESV.exe from TESV.exe.previous (one-step undo of the last patch).
bool RestoreFromPrevious(const std::string& exePath);

}
