#pragma once

namespace overdrive::dxbc {

// Walk every shader captured by ResourceMirror. For each, parse the D3D9
// bytecode header, count instructions per opcode, classify by shader-model.
// Aggregate everything and dump a single report to the log.
//
// What this answers:
//   - What SM versions does Skyrim actually use? (SM1.x / SM2.0 / SM2.x / SM3.0)
//   - What opcodes appear, and how often? (mov / dp4 / texld / etc.)
//   - Are there any "fancy" features in use (loops, branches, predication)?
//
// This sizes the DXBC->SPIR-V translator work: instead of implementing all
// of D3D9 SM3, implement only the opcodes that actually appear, in the
// SM versions actually used.
//
// `Run()` is one-shot. Throttled internally so it only runs once per game
// session (after the bulk of shaders have been created). Call from any
// thread; iterates ResourceMirror tables under their internal locks.
void Run();

// Throttled internally to once per session. Call from worker loop.
void MaybeRun();

}
