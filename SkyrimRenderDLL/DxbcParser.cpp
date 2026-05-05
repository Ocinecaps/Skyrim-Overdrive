#include "DxbcParser.h"

#include <cstdio>
#include <cstring>

namespace overdrive::dxbc {

namespace {

constexpr uint32_t kEnd = 0x0000FFFF;
constexpr uint16_t kComment = 0xFFFE;
constexpr uint16_t kPhase   = 0xFFFD;

// 5-bit register type, split per D3DSP_REGTYPE_MASK / _MASK2 in d3d9types.h:
//   bits [28..30] = LOW 3 bits of the type value (D3DSP_REGTYPE_SHIFT = 28)
//   bits [11..12] = HIGH 2 bits of the type value
//   Bit 13 is ADDRESSING MODE — must NOT be included in the reg-type read.
//
// The previous version of this function treated bits [11..13] as the LOW 3
// and bits [28..30] as the HIGH 3 (and used `(hi<<3)|lo`), which silently
// broke 865/879 shader translations: every D3DSPR_CONST destination (used
// by every `def cN, ...` instruction in a VS) decoded as RegType(16) =
// TempFloat16, hitting the unsupported-reg-type fail bucket. With the
// correct extraction, CONST = 2 and we can route `def` cleanly.
RegType DecodeRegType(uint32_t tok) {
    uint32_t low3  = (tok >> 28) & 0x7;   // D3DSP_REGTYPE_MASK
    uint32_t high2 = (tok >> 11) & 0x3;   // D3DSP_REGTYPE_MASK2 (2 bits, not 3)
    uint32_t t     = (high2 << 3) | low3;
    return static_cast<RegType>(t);
}

DstParam DecodeDst(uint32_t tok) {
    DstParam d{};
    d.raw       = tok;
    d.type      = DecodeRegType(tok);
    d.index     = static_cast<uint16_t>(tok & 0x7FF);
    d.writeMask = static_cast<uint8_t>((tok >> 16) & 0xF);
    d.modifier  = static_cast<uint8_t>((tok >> 20) & 0xF);
    d.shift     = static_cast<uint8_t>((tok >> 24) & 0xF);
    return d;
}

SrcParam DecodeSrc(uint32_t tok) {
    SrcParam s{};
    s.raw      = tok;
    s.type     = DecodeRegType(tok);
    s.index    = static_cast<uint16_t>(tok & 0x7FF);
    s.swizzle  = static_cast<uint8_t>((tok >> 16) & 0xFF);
    s.modifier = static_cast<uint8_t>((tok >> 24) & 0xF);
    return s;
}

// Number of source operands per opcode. Indices match D3DSIO_* values.
// 0 = no source (or "we skip via length field"); -1 = special-cased
// elsewhere (def, dcl, comments).
int8_t SrcCountFor(uint16_t op) {
    switch (op) {
        // 0-source
        case 0:  return 0;   // nop
        case 27: return 0;   // loop  (uses i# constant; argless from src perspective)
        case 28: return 0;   // ret
        case 29: return 0;   // endloop
        case 38: return 0;   // rep
        case 39: return 0;   // endrep
        case 42: return 0;   // else
        case 43: return 0;   // endif
        case 44: return 0;   // break
        case 30: return 1;   // label
        // 1-source ALU
        case 1:  return 1;   // mov
        case 6:  return 1;   // rcp
        case 7:  return 1;   // rsq
        case 14: return 1;   // exp
        case 15: return 1;   // log
        case 16: return 1;   // lit
        case 19: return 1;   // frc
        case 31: return 1;   // dcl  (special — handled below)
        case 34: return 1;   // sgn
        case 35: return 1;   // abs
        case 36: return 1;   // nrm
        case 37: return 1;   // sincos (sm2: 3 srcs, sm3: 1 — we treat as 1 + skip)
        case 46: return 1;   // mova
        case 78: return 1;   // expp
        case 79: return 1;   // logp
        case 87: return 1;   // texdepth (operates on dst)
        case 91: return 1;   // dsx
        case 92: return 1;   // dsy
        // 2-source ALU
        case 2:  return 2;   // add
        case 3:  return 2;   // sub
        case 5:  return 2;   // mul
        case 8:  return 2;   // dp3
        case 9:  return 2;   // dp4
        case 10: return 2;   // min
        case 11: return 2;   // max
        case 12: return 2;   // slt
        case 13: return 2;   // sge
        case 32: return 2;   // pow
        case 33: return 2;   // crs
        case 65: return 1;   // texkill
        case 66: return 2;   // tex/texld (sm2+: dst, src0=coord, src1=sampler)
        // 3-source
        case 4:  return 3;   // mad
        case 18: return 3;   // lrp
        case 88: return 3;   // cmp
        case 90: return 3;   // dp2add
        case 94: return 2;   // setp (controls = comparison op; 2 src operands)
        case 80: return 3;   // cnd
        case 95: return 2;   // texldl (dst, coord, sampler)
        case 89: return 2;   // bem
        // matrix-flavored — destination-mask+matrix flag, count via length field
        case 20: return 2;   // m4x4
        case 21: return 2;   // m4x3
        case 22: return 2;   // m3x4
        case 23: return 2;   // m3x3
        case 24: return 2;   // m3x2
        // call/branch
        case 25: return 1;   // call
        case 26: return 2;   // callnz
        case 40: return 1;   // if
        case 41: return 2;   // ifc
        case 45: return 2;   // breakc
        case 96: return 1;   // breakp
        // texture-coord (sm1)
        case 64: return 0;   // texcoord (dst only)
        case 67: return 1;   // texbem
        case 68: return 1;   // texbeml
        case 69: return 1;   // texreg2ar
        case 70: return 1;   // texreg2gb
        case 71: return 1;   // texm3x2pad
        case 72: return 1;   // texm3x2tex
        case 73: return 1;   // texm3x3pad
        case 74: return 1;   // texm3x3tex
        case 76: return 2;   // texm3x3spec
        case 77: return 1;   // texm3x3vspec
        case 82: return 1;   // texreg2rgb
        case 83: return 2;   // texdp3tex
        case 84: return 1;   // texm3x2depth
        case 85: return 1;   // texdp3
        case 86: return 1;   // texm3x3
        // def/defi/defb — special (handled separately, 4 literal dwords follow dst)
        case 47: return 0;   // defb
        case 48: return 0;   // defi
        case 81: return 0;   // def
        // sampler-load with extended args (texldd in sm3)
        case 93: return 4;   // texldd  (dst, coord, sampler, ddx, ddy)
        default: return -1;  // unknown — fall back to length-field skip
    }
}

bool OpHasDst(uint16_t op) {
    switch (op) {
        // Pure flow control / no destination register
        case 0:   // nop
        case 25:  // call
        case 26:  // callnz
        case 27:  // loop
        case 28:  // ret
        case 29:  // endloop
        case 38:  // rep
        case 39:  // endrep
        case 40:  // if
        case 41:  // ifc
        case 42:  // else
        case 43:  // endif
        case 44:  // break
        case 45:  // breakc
        case 96:  // breakp
        case 30:  // label
        case 65:  // texkill (operates on dst register but no write)
            return false;
        default:
            return true;
    }
}

}  // namespace

Decoded Decode(const uint32_t* bc, size_t dwords) {
    Decoded out{};
    out.ok = false;
    if (!bc || dwords < 2) { out.errMsg = "bytecode too short"; return out; }

    uint32_t version = bc[0];
    uint16_t type    = (version >> 16) & 0xFFFF;
    out.major = (version >> 8) & 0xFF;
    out.minor = (version)      & 0xFF;
    if (type == 0xFFFE)      out.isPixelShader = false;
    else if (type == 0xFFFF) out.isPixelShader = true;
    else                     { out.errMsg = "bad version token"; return out; }

    size_t i = 1;
    while (i < dwords) {
        uint32_t tok = bc[i];
        if (tok == kEnd) break;

        uint16_t op       = tok & 0xFFFF;
        uint8_t  controls = (tok >> 16) & 0xFF;
        uint8_t  len      = (tok >> 24) & 0x0F;
        bool     pred     = (tok & (1u << 28)) != 0;

        // Comment: length encoded in bits 30..16, skip whole block.
        if (op == kComment) {
            uint32_t commentLen = (tok >> 16) & 0x7FFF;
            i += 1 + commentLen;
            continue;
        }
        // Phase token (sm1.4): no operands.
        if (op == kPhase) { ++i; continue; }

        // Build instruction.
        Instruction in{};
        in.opcode     = op;
        in.controls   = controls;
        in.predicated = pred;
        in.hasDst     = false;
        in.hasLiterals = false;

        size_t opStart = i;
        size_t cursor  = i + 1;

        // Special-case def/defi/defb: dst then 4 literal dwords.
        if (op == 81 /*def*/ || op == 48 /*defi*/ || op == 47 /*defb*/) {
            if (cursor + 1 + 4 > dwords) { out.errMsg = "truncated def"; return out; }
            in.hasDst = true;
            in.dst    = DecodeDst(bc[cursor++]);
            in.hasLiterals = true;
            std::memcpy(in.literals, &bc[cursor], 16);
            cursor += 4;
            out.ins.push_back(in);
            // Length field tells us where to actually jump (covers any padding).
            i = (len > 0) ? (opStart + 1 + len) : cursor;
            continue;
        }

        // dcl: dst + (sometimes) usage token first. Handle as: skip bytes
        // declared in length field; record opcode only (no analytical use yet).
        if (op == 31 /*dcl*/) {
            in.hasDst = (len >= 2);  // dcl_xxx <usage> <dst>
            // We don't try to fully decode dcl yet — record opcode and move on.
            out.ins.push_back(in);
            i = opStart + 1 + (len ? len : 2);
            continue;
        }

        // Standard path.
        if (OpHasDst(op)) {
            if (cursor >= dwords) { out.errMsg = "truncated dst"; return out; }
            in.hasDst = true;
            in.dst    = DecodeDst(bc[cursor++]);
            // A dst with relative addressing has an extra dword (a0.x register
            // reference) — bits 14..13 of dst token tell us. We don't yet
            // surface that, but we advance past it.
            uint8_t relAddr = (in.dst.raw >> 13) & 0x3;
            if (relAddr) { ++cursor; }
        }

        int8_t srcN = SrcCountFor(op);
        if (srcN < 0) {
            // Unknown opcode — fall back to length-field skip.
            out.ins.push_back(in);
            i = opStart + 1 + (len ? len : 1);
            continue;
        }
        for (int s = 0; s < srcN; ++s) {
            if (cursor >= dwords) { out.errMsg = "truncated src"; return out; }
            uint32_t srcTok = bc[cursor++];
            // Relative addressing on a source: an extra dword follows.
            uint8_t relAddr = (srcTok >> 13) & 0x3;
            if (relAddr) {
                if (cursor >= dwords) { out.errMsg = "truncated relAddr"; return out; }
                ++cursor;
            }
            in.srcs.push_back(DecodeSrc(srcTok));
        }

        out.ins.push_back(in);

        // Reconcile: if length field says more, trust it (skips any extra
        // dwords for opcodes we modeled with too few sources).
        size_t expectedNext = opStart + 1 + (len ? len : (cursor - opStart - 1));
        if (expectedNext > cursor) cursor = expectedNext;
        i = cursor;
    }

    out.ok = true;
    return out;
}

namespace {
const char* RegTypeShortName(RegType t) {
    switch (t) {
        case RegType::Temp:        return "r";
        case RegType::Input:       return "v";
        case RegType::Const:       return "c";
        case RegType::Addr:        return "a";
        case RegType::RastOut:     return "oRast";
        case RegType::AttrOut:     return "oAttr";
        case RegType::TexCrdOut:   return "oTC";
        case RegType::ColorOut:    return "oC";
        case RegType::DepthOut:    return "oDepth";
        case RegType::Sampler:     return "s";
        case RegType::ConstBool:   return "b";
        case RegType::ConstInt:    return "i";
        case RegType::Loop:        return "aL";
        case RegType::MiscType:    return "vMisc";
        case RegType::Predicate:   return "p";
        default:                   return "?";
    }
}
const char* OpcodeMnemonic(uint16_t op) {
    switch (op) {
        case 0:  return "nop"; case 1:  return "mov"; case 2:  return "add";
        case 3:  return "sub"; case 4:  return "mad"; case 5:  return "mul";
        case 6:  return "rcp"; case 7:  return "rsq"; case 8:  return "dp3";
        case 9:  return "dp4"; case 10: return "min"; case 11: return "max";
        case 14: return "exp"; case 15: return "log"; case 16: return "lit";
        case 18: return "lrp"; case 19: return "frc"; case 20: return "m4x4";
        case 21: return "m4x3"; case 22: return "m3x4"; case 23: return "m3x3";
        case 24: return "m3x2"; case 25: return "call"; case 27: return "loop";
        case 28: return "ret"; case 29: return "endloop"; case 31: return "dcl";
        case 32: return "pow"; case 35: return "abs"; case 36: return "nrm";
        case 40: return "if"; case 41: return "ifc"; case 42: return "else";
        case 43: return "endif"; case 44: return "break"; case 46: return "mova";
        case 47: return "defb"; case 48: return "defi"; case 65: return "texkill";
        case 66: return "tex"; case 81: return "def"; case 88: return "cmp";
        case 90: return "dp2add"; case 93: return "texldd"; case 95: return "texldl";
        default: return "op?";
    }
}
}  // namespace

int Disassemble(const Instruction& ins, char* buf, size_t bufLen) {
    if (!buf || bufLen == 0) return 0;
    int n = std::snprintf(buf, bufLen, "%s%s", OpcodeMnemonic(ins.opcode),
                          ins.predicated ? "(p)" : "");
    if (ins.hasDst) {
        n += std::snprintf(buf + n, bufLen - (size_t)n, " %s%u",
                           RegTypeShortName(ins.dst.type), ins.dst.index);
        if (ins.dst.writeMask != WriteMaskAll) {
            char m[8] = {}; int j = 0;
            if (ins.dst.writeMask & WriteMaskX) m[j++] = 'x';
            if (ins.dst.writeMask & WriteMaskY) m[j++] = 'y';
            if (ins.dst.writeMask & WriteMaskZ) m[j++] = 'z';
            if (ins.dst.writeMask & WriteMaskW) m[j++] = 'w';
            n += std::snprintf(buf + n, bufLen - (size_t)n, ".%s", m);
        }
    }
    for (size_t s = 0; s < ins.srcs.size(); ++s) {
        n += std::snprintf(buf + n, bufLen - (size_t)n, "%s %s%u",
                           s == 0 ? "," : ",",
                           RegTypeShortName(ins.srcs[s].type),
                           ins.srcs[s].index);
    }
    if (ins.hasLiterals) {
        n += std::snprintf(buf + n, bufLen - (size_t)n,
                           " {%g, %g, %g, %g}",
                           ins.literals[0], ins.literals[1],
                           ins.literals[2], ins.literals[3]);
    }
    return n;
}

}
