#pragma once

namespace overdrive::crashdbg {

// Install an unhandled-exception filter (`SetUnhandledExceptionFilter`) that
// runs ONLY when no Skyrim/SKSE/ENB SEH handler caught a fatal exception.
// Inside the handler we:
//   1. Capture the crashing context (EIP, ESP, EBP, all GP regs).
//   2. Walk the stack via dbghelp `StackWalk64`.
//   3. Symbolicate each frame:
//        - Windows DLLs (ntdll, kernel32, d3d9, ...) via SymFromAddr (PDBs
//          downloaded from the public symbol server).
//        - TESV.exe addresses via our own table built from the user's IDA
//          extractions (filenames like `xrefs_API_NNN_0xVVVVVVVV.txt` and
//          subfolder names like `sub_NNNNNN` carry every known function VA).
//   4. Dump everything to `skyrim_overdrive_crash.log` next to the game.
//
// Then we let the OS continue (EXCEPTION_CONTINUE_SEARCH) — the process
// still terminates / WER dialog still appears, we just leave a forensic
// trace behind. Without this, every invasive EXE patch that breaks the
// game leaves us no information about WHERE in TESV.exe execution was
// when it crashed.
//
// `Install` enumerates IDA extraction filenames once at startup. Cost is a
// few hundred ms scanning the user's `ida scripts and extracted` folder.
// All later lookups are O(log N) binary searches on a sorted in-memory
// table.
//
// Returns true if the filter was installed (it can fail if SetUnhandled-
// ExceptionFilter is itself hooked by another process / debugger).
bool Install();

void Shutdown();

// Public for unit testing / sanity checks. Returns the symbol name for a
// TESV.exe VA, or "?" if not in the table.
const char* ResolveTesvAddr(unsigned long va, unsigned long* outOffset);

// Returns true if `va` is plausibly a TESV.exe code address — i.e., it sits
// within `withinBytes` of a known function start in our IDA-extraction
// symbol table. Used by the wait-site sampler to filter out stale data-
// section pointers that happen to be in TESV.exe's address range but are
// NOT real return addresses (vtables, strings, globals, etc.).
//
// Pass `withinBytes = 0x10000` (64 KB) for a generous-but-effective filter:
// any return address inside any normal-sized TESV.exe function will be
// within 64 KB of that function's start (TESV's largest functions are
// ~10-20 KB).
bool IsTesvCodeAddr(unsigned long va, unsigned long withinBytes);

}
