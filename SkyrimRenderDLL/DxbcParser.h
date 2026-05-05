#pragma once
#include <cstdint>
#include <vector>

namespace overdrive::dxbc {

// =============================================================================
// DxbcParser — D3D9 shader bytecode -> structured intermediate form
// =============================================================================
//
// DxbcAnalyzer answers "what opcodes appear, how often". This module is the
// next layer up: it decodes a single shader's bytecode into a list of
// structured Instructions that the translator (Phase A.3c) walks to emit
// SPIR-V.
//
// Why a separate module: the analyzer is throwaway statistics. The decoder
// is the load-bearing path that every shader translation will go through.
// Keeping the structured-IR API stable while the translator's opcode
// coverage grows means we can ship the translator opcode-by-opcode.
//
// Reference: D3D9 shader bytecode spec — Microsoft DirectX 9 docs.
//
// Token format quick reference:
//   Source-parameter token:
//     bits 10..0   register number
//     bits 13..11  reg-type[2..0]
//     bits 15..14  relative-addressing
//     bits 23..16  swizzle (4x 2-bit)  (xyzw = 0,1,2,3)
//     bits 27..24  source modifier
//     bits 30..28  reg-type[5..3]   (combined with bits 13..11 = 6-bit register type)
//     bit  31      always 1
//   Destination-parameter token:
//     bits 10..0   register number
//     bits 13..11  reg-type[2..0]
//     bits 15..14  relative-addressing
//     bits 19..16  write mask  (bit per channel: x=1, y=2, z=4, w=8)
//     bits 23..20  destination modifier
//     bits 27..24  shift scale
//     bits 30..28  reg-type[5..3]
//     bit  31      always 1
//
// Register types we care about (combined 6-bit field):
//   0x0  TEMP        rN
//   0x1  INPUT       vN
//   0x2  CONST       cN
//   0x3  ADDR (vs) / TEXTURE (ps)
//   0x4  RASTOUT     oPos / oFog / oPts
//   0x5  ATTROUT     oDN
//   0x6  TEXCRDOUT (vs) / OUTPUT (vs sm3) / INPUT (ps sm3)
//   0xA  COLOROUT
//   0xB  DEPTHOUT
//   0xC  SAMPLER     sN
//   0xD  CONST2      cN[]   (extended)
//   0xE  CONST3
//   0xF  CONST4
//   0x10 CONSTBOOL   bN
//   0x11 CONSTINT    iN
//   0x12 LOOP        aL
//   0x13 TEMPFLOAT16
//   0x14 MISCTYPE    vPos / vFace
//   0x15 LABEL
//   0x16 PREDICATE   p0

// Values are the D3DSPR_* enum from <d3d9types.h>. The previous version of
// this enum had wrong numeric values for everything from ColorOut onward —
// real D3D9 bytecode uses the values below, and our DecodeRegType() returns
// these directly. Mismatching them silently broke 878/879 VS translations.
enum class RegType : uint8_t {
    Temp        = 0,
    Input       = 1,
    Const       = 2,
    Addr        = 3,    // also Texture in ps_1_*
    RastOut     = 4,
    AttrOut     = 5,    // oD0/oD1 in vs_2_x — vertex color outputs
    TexCrdOut   = 6,    // also Output in vs_3_0
    ConstInt    = 7,
    ColorOut    = 8,
    DepthOut    = 9,
    Sampler     = 10,
    Const2      = 11,
    Const3      = 12,
    Const4      = 13,
    ConstBool   = 14,
    Loop        = 15,
    TempFloat16 = 16,
    MiscType    = 17,   // vPos / vFace in ps_3_0
    Label       = 18,
    Predicate   = 19,
    Unknown     = 0xFF,
};

constexpr uint8_t WriteMaskX = 0x1;
constexpr uint8_t WriteMaskY = 0x2;
constexpr uint8_t WriteMaskZ = 0x4;
constexpr uint8_t WriteMaskW = 0x8;
constexpr uint8_t WriteMaskAll = 0xF;

struct DstParam {
    RegType  type;
    uint16_t index;
    uint8_t  writeMask;     // 4-bit
    uint8_t  shift;         // bits 27..24 — _x2, _x4, _d2 etc.
    uint8_t  modifier;      // bits 23..20 — saturate, partial precision
    uint32_t raw;
};

struct SrcParam {
    RegType  type;
    uint16_t index;
    uint8_t  swizzle;       // packed 4x 2-bit channels (xyzw=0123)
    uint8_t  modifier;      // bits 27..24 — _neg, _abs, etc.
    uint32_t raw;

    // Decode a single channel (0=x .. 3=w) of the swizzle into a source
    // channel index 0..3.
    uint8_t Channel(int dst) const { return (swizzle >> (dst * 2)) & 0x3; }
};

struct Instruction {
    uint16_t opcode;        // D3DSIO_* value
    uint8_t  controls;      // bits 23..16 — comparison op for setp/breakc, etc.
    bool     predicated;    // bit 28 of token
    bool     hasDst;
    DstParam dst;
    std::vector<SrcParam> srcs;

    // Some instructions carry literal data: def cN, f0, f1, f2, f3 — 4 floats
    // of inline data after the dst token. Stored here when present.
    bool             hasLiterals;
    float            literals[4];
};

struct Decoded {
    bool     ok;            // false if bytecode was malformed
    bool     isPixelShader; // false = vertex
    uint8_t  major;
    uint8_t  minor;
    std::vector<Instruction> ins;

    // Quick error string for the "not ok" case — set when ok=false.
    const char* errMsg;
};

// Decode a single shader's bytecode (DWORD stream including version token,
// terminated by 0x0000FFFF). The returned Decoded is self-contained.
Decoded Decode(const uint32_t* bc, size_t dwords);

// Diagnostic — render a decoded instruction to a human-readable string for
// the log. Useful when validating the decoder against a known shader.
// Returns number of bytes written (excluding NUL).
int Disassemble(const Instruction& ins, char* buf, size_t bufLen);

}
