#pragma once
#include <cstdint>
#include <vector>

namespace overdrive::dxbc { struct Decoded; }

namespace overdrive::dxbc_spirv {

// =============================================================================
// DxbcToSpirv — translates a dxbc::Decoded shader into a binary SPIR-V module
// =============================================================================
//
// This is the emit-side scaffold for Phase A.3c. The full opcode coverage is
// added incrementally — what's here today is enough to:
//   1. Emit a minimal structurally-valid SPIR-V vertex shader (passthrough).
//   2. Emit a minimal structurally-valid SPIR-V fragment shader (red).
//   3. Provide a Translate(Decoded&) entry point that today calls into one
//      of the two minimal emitters based on shader type, but is the place
//      where real opcode-by-opcode translation will land.
//
// Validating the minimum modules through vkCreateShaderModule confirms the
// SpirvBuilder produces correct binary layout. Once that's green, the rest
// of the work is pure ALU translation in the IR-walking case below.

// Build a passthrough VS:
//   layout(location=0) in vec4 inPos;
//   void main() { gl_Position = inPos; }
std::vector<uint32_t> EmitMinimalVS();

// Build a constant-color PS that writes red to color attachment 0:
//   layout(location=0) out vec4 outColor;
//   void main() { outColor = vec4(1,0,0,1); }
std::vector<uint32_t> EmitMinimalPS();

// Top-level translator entry point. Walks dec.ins emitting one SPIR-V
// instruction per supported D3D9 opcode. Returns an empty vector on any
// structural failure or unsupported feature; caller can read `lastFailReason`
// (thread-unsafe quick-and-dirty diagnostic) to bucket failures.
//
// For unsupported PS shaders or VS shaders using unimplemented opcodes,
// callers can fall back to the minimal scaffold via EmitMinimalVS/PS to keep
// the pipeline path alive (the resulting render won't be correct but the
// VkPipeline will compile, so we can still measure end-to-end progress).
std::vector<uint32_t> Translate(const overdrive::dxbc::Decoded& dec);

// Last failure reason from Translate(). Set when Translate() returns empty.
// Static char buffer — not thread-safe; intended for boot-time diagnostics
// only.
const char* LastFailReason();

// Counters distinguishing real translation success from passthrough fallback.
// "Real" = the Translator class handled the shader's opcodes. "Passthrough"
// = the shader was outside the current opcode allowlist and we emitted a
// minimal scaffold so the pipeline path stays testable. Sum of the two =
// total successful Translate() calls.
uint32_t TranslatedRealCount();
uint32_t TranslatedPassthroughCount();

}
