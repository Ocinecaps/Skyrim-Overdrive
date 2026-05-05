#pragma once
#include <string>

namespace patcher {

// Apply all known byte-splice patches to the unpacked TESV.exe in-place.
//
// Each patch is a `{ va, originalBytes, patchedBytes, description }` tuple.
// Before writing, the original bytes are verified — so if Skyrim updates the
// binary or another tool patches first, we abort that patch instead of
// corrupting the code.
//
// Each successfully-applied patch is logged. The set is small and curated;
// append new patches in BytePatches.cpp's g_patches[] array.
//
// Returns true if all patches applied (or were already applied — idempotent).
// Returns false if any patch verifies neither original nor patched bytes
// (i.e., the binary has unfamiliar content at that VA).
bool ApplyBytePatches(const std::string& exePath);

// Reverts all byte-splice patches. Used by the .original/.previous restore
// paths to ensure a fully-pristine exe (those paths just copy the file —
// they don't need this — but it's here for completeness).
bool RevertBytePatches(const std::string& exePath);

}
