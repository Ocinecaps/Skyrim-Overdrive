#include "DxbcAnalyzer.h"
#include "DxbcParser.h"
#include "DxbcToSpirv.h"
#include "ResourceMirror.h"
#include "DebugLogger.h"
#include <map>
#include <string>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>

namespace overdrive::dxbc {

namespace {

// =============================================================================
// D3D9 bytecode token format (subset we care about for analysis)
// =============================================================================
//
// Version token (always first DWORD):
//   bits 31..16 = type:    0xFFFE = vertex shader, 0xFFFF = pixel shader
//   bits 15..8  = major version
//   bits  7..0  = minor version  (often 0; values like 0x00 or 0xA0 / 0xB0
//                                 distinguish SM2.0 / SM2.x / SM3.0)
//
// Instruction token:
//   bits 15..0  = opcode (D3DSIO_*)
//   bits 23..16 = controls / specific-opcode bits
//   bits 27..24 = instruction length (DWORDs after the opcode token)
//   bit  28     = predicated
//   bits 30..29 = co-issue / paired
//   bit  31     = always 0
//
// Terminator: 0x0000FFFF
//
// We don't need to fully decode each instruction — just identify the opcode
// and skip past the instruction's parameter dwords using bits 27..24.

constexpr uint32_t kEnd = 0x0000FFFF;

constexpr uint16_t TYPE_VS = 0xFFFE;
constexpr uint16_t TYPE_PS = 0xFFFF;

// Opcode names — D3DSIO_* values. Source: Microsoft DirectX 9 docs.
const char* OpcodeName(uint16_t op) {
    switch (op) {
        case 0:  return "nop";
        case 1:  return "mov";
        case 2:  return "add";
        case 3:  return "sub";
        case 4:  return "mad";
        case 5:  return "mul";
        case 6:  return "rcp";
        case 7:  return "rsq";
        case 8:  return "dp3";
        case 9:  return "dp4";
        case 10: return "min";
        case 11: return "max";
        case 12: return "slt";
        case 13: return "sge";
        case 14: return "exp";
        case 15: return "log";
        case 16: return "lit";
        case 17: return "dst";
        case 18: return "lrp";
        case 19: return "frc";
        case 20: return "m4x4";
        case 21: return "m4x3";
        case 22: return "m3x4";
        case 23: return "m3x3";
        case 24: return "m3x2";
        case 25: return "call";
        case 26: return "callnz";
        case 27: return "loop";
        case 28: return "ret";
        case 29: return "endloop";
        case 30: return "label";
        case 31: return "dcl";
        case 32: return "pow";
        case 33: return "crs";
        case 34: return "sgn";
        case 35: return "abs";
        case 36: return "nrm";
        case 37: return "sincos";
        case 38: return "rep";
        case 39: return "endrep";
        case 40: return "if";
        case 41: return "ifc";
        case 42: return "else";
        case 43: return "endif";
        case 44: return "break";
        case 45: return "breakc";
        case 46: return "mova";
        case 47: return "defb";
        case 48: return "defi";
        case 64: return "texcoord";
        case 65: return "texkill";
        case 66: return "tex/texld";
        case 67: return "texbem";
        case 68: return "texbeml";
        case 69: return "texreg2ar";
        case 70: return "texreg2gb";
        case 71: return "texm3x2pad";
        case 72: return "texm3x2tex";
        case 73: return "texm3x3pad";
        case 74: return "texm3x3tex";
        case 76: return "texm3x3spec";
        case 77: return "texm3x3vspec";
        case 78: return "expp";
        case 79: return "logp";
        case 80: return "cnd";
        case 81: return "def";
        case 82: return "texreg2rgb";
        case 83: return "texdp3tex";
        case 84: return "texm3x2depth";
        case 85: return "texdp3";
        case 86: return "texm3x3";
        case 87: return "texdepth";
        case 88: return "cmp";
        case 89: return "bem";
        case 90: return "dp2add";
        case 91: return "dsx";
        case 92: return "dsy";
        case 93: return "texldd";
        case 94: return "setp";
        case 95: return "texldl";
        case 96: return "breakp";
        case 0xFFFD: return "phase";
        case 0xFFFE: return "comment";
        default:    return nullptr;
    }
}

struct Aggregate {
    int  totalShaders = 0;
    int  totalInstructions = 0;
    int  smHistogram[16] = {};   // index = (major<<4) | (minor>>4) — minor is 0/A/B
    int  smCounts[4]     = {};   // SM1=0, SM2=1, SM2x=2, SM3=3
    int  opcodeCounts[256] = {}; // 0..255
    int  highOpcodeCount   = 0;  // anything >= 256
    int  malformed         = 0;
    int  controlFlowShaders = 0; // shaders containing if/loop/call
    bool parserDumpedFirst = false;
    int parserOk      = 0;
    int parserFailed  = 0;

    // Step 2 translator self-check: how many shaders make it cleanly through
    // DxbcToSpirv::Translate(). Each failure reason is bucketed so we can
    // pick the most-impactful next opcode to add. This is the load-bearing
    // metric for translator coverage progression.
    int translatorOk = 0;
    int translatorFailed = 0;
    std::map<std::string, int> failBuckets;
};

void AnalyzeOne(const uint32_t* bc, size_t dwords, Aggregate& agg, uint16_t expectType) {
    if (dwords == 0 || !bc) { ++agg.malformed; return; }
    uint32_t version = bc[0];
    uint16_t type    = (version >> 16) & 0xFFFF;
    uint8_t  major   = (version >> 8)  & 0xFF;
    uint8_t  minor   = (version)       & 0xFF;
    if (type != expectType) { ++agg.malformed; return; }

    // Classify SM version. Minor 0xA0/0xB0 = "SM 2.x" extended. Minor 0x00 = base.
    int smBucket = 0;
    if (major <= 1)        smBucket = 0;
    else if (major == 2 && minor == 0)        smBucket = 1;
    else if (major == 2 && (minor == 0xA || minor == 0xB || minor >= 0x80))
                                              smBucket = 2;   // SM 2.x
    else if (major >= 3)   smBucket = 3;
    else                   smBucket = 1;   // default to SM2.0
    if (smBucket >= 0 && smBucket < 4) ++agg.smCounts[smBucket];

    bool sawControlFlow = false;

    // Walk instructions starting at index 1.
    size_t i = 1;
    while (i < dwords) {
        uint32_t tok = bc[i];
        if (tok == kEnd) break;
        uint16_t op  = tok & 0xFFFF;
        uint8_t  len = (tok >> 24) & 0x0F;
        // Special case: comment token has length in bits 30..16.
        if (op == 0xFFFE) {
            uint32_t commentLen = (tok >> 16) & 0x7FFF;
            i += 1 + commentLen;
            continue;
        }
        if (op < 256) ++agg.opcodeCounts[op];
        else          ++agg.highOpcodeCount;
        ++agg.totalInstructions;

        // Detect control flow.
        if (op == 25 || op == 26 || op == 27 || op == 38 ||
            op == 40 || op == 41 || op == 44 || op == 45 || op == 96) {
            sawControlFlow = true;
        }

        // Skip past this instruction. len=0 means "end-stream marker for this
        // op" or a fixed 0-arg instruction; we just advance by 1 to be safe.
        if (len == 0) ++i;
        else          i += 1 + len;
    }

    if (sawControlFlow) ++agg.controlFlowShaders;
    ++agg.totalShaders;

    // DxbcParser self-check: decode this same shader through the structured
    // IR path. If the parser succeeds and produces a non-empty instruction
    // stream, it stays in sync with the analyzer. The first VS and first PS
    // also get a 12-line disassembly preview dumped to the log — gives us a
    // visible signal that the parser is doing the right thing.
    Decoded dec = Decode(bc, dwords);
    if (dec.ok && !dec.ins.empty()) {
        ++agg.parserOk;
        if (!agg.parserDumpedFirst) {
            agg.parserDumpedFirst = true;
            const char* kind = (expectType == TYPE_PS) ? "PS" : "VS";
            OD_LOG("[DxbcAnalyzer] First %s decoded by DxbcParser: sm%u.%u, %zu instructions. First 12:",
                   kind, dec.major, dec.minor, dec.ins.size());
            size_t cap = dec.ins.size() < 12 ? dec.ins.size() : 12;
            for (size_t k = 0; k < cap; ++k) {
                char buf[256];
                Disassemble(dec.ins[k], buf, sizeof(buf));
                OD_LOG("[DxbcAnalyzer]   %02zu: %s", k, buf);
            }
        }

        // Step 2 translator self-check — run every parsed shader through
        // DxbcToSpirv::Translate. Successes get counted; failures get
        // bucketed by reason so we know what to implement next.
        std::vector<uint32_t> spirv = dxbc_spirv::Translate(dec);
        if (!spirv.empty()) {
            ++agg.translatorOk;
        } else {
            ++agg.translatorFailed;
            const char* why = dxbc_spirv::LastFailReason();
            agg.failBuckets[why ? why : "(unknown)"]++;
        }
    } else {
        ++agg.parserFailed;
    }
}

void VsVisitor(const void*, const uint32_t* bc, size_t dwords, void* user) {
    AnalyzeOne(bc, dwords, *reinterpret_cast<Aggregate*>(user), TYPE_VS);
}
void PsVisitor(const void*, const uint32_t* bc, size_t dwords, void* user) {
    AnalyzeOne(bc, dwords, *reinterpret_cast<Aggregate*>(user), TYPE_PS);
}

void DumpReport(const char* label, const Aggregate& agg) {
    OD_LOG("[DxbcAnalyzer] %s shaders analyzed: %d total, %d malformed, "
           "%d total instructions, %d shaders use control flow",
           label, agg.totalShaders, agg.malformed,
           agg.totalInstructions, agg.controlFlowShaders);
    OD_LOG("[DxbcAnalyzer] %s SM distribution:  SM1.x=%d  SM2.0=%d  SM2.x=%d  SM3.0=%d",
           label, agg.smCounts[0], agg.smCounts[1],
           agg.smCounts[2], agg.smCounts[3]);
    OD_LOG("[DxbcAnalyzer] %s parser self-check: %d ok, %d failed (target: failed=0)",
           label, agg.parserOk, agg.parserFailed);

    // Translator coverage metric — the actual progress signal.
    int totalTried = agg.translatorOk + agg.translatorFailed;
    if (totalTried > 0) {
        OD_LOG("[DxbcAnalyzer] %s translator coverage: %d/%d (%.1f%%) translate "
               "to SPIR-V cleanly. Top fail buckets (next opcodes to implement):",
               label, agg.translatorOk, totalTried,
               (100.0 * agg.translatorOk) / totalTried);
        // Print the top 8 fail buckets sorted by count.
        std::vector<std::pair<std::string,int>> fails(agg.failBuckets.begin(),
                                                       agg.failBuckets.end());
        std::sort(fails.begin(), fails.end(),
                  [](auto& x, auto& y){ return x.second > y.second; });
        size_t cap = fails.size() < 8 ? fails.size() : 8;
        for (size_t i = 0; i < cap; ++i) {
            OD_LOG("[DxbcAnalyzer]   fail#%zu  count=%d  reason=\"%s\"",
                   i + 1, fails[i].second, fails[i].first.c_str());
        }
    }

    // Build a sorted opcode list and print top entries.
    std::vector<std::pair<int, int>> entries; // <opcode, count>
    entries.reserve(64);
    for (int op = 0; op < 256; ++op) {
        if (agg.opcodeCounts[op] > 0) {
            entries.emplace_back(op, agg.opcodeCounts[op]);
        }
    }
    std::sort(entries.begin(), entries.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    int distinct = (int)entries.size();
    OD_LOG("[DxbcAnalyzer] %s opcode histogram: %d distinct opcodes used. Top 25:",
           label, distinct);
    int n = (int)entries.size();
    if (n > 25) n = 25;
    for (int i = 0; i < n; ++i) {
        int op = entries[i].first;
        int cnt = entries[i].second;
        const char* name = OpcodeName((uint16_t)op);
        double pct = (100.0 * cnt) / (double)agg.totalInstructions;
        if (name) {
            OD_LOG("[DxbcAnalyzer]   #%-2d  op=%-3d  %-12s  count=%d  %.2f%%",
                   i + 1, op, name, cnt, pct);
        } else {
            OD_LOG("[DxbcAnalyzer]   #%-2d  op=%-3d  (unknown)     count=%d  %.2f%%",
                   i + 1, op, cnt, pct);
        }
    }
    if (distinct > 25) {
        int hidden = 0;
        for (size_t i = 25; i < entries.size(); ++i) hidden += entries[i].second;
        OD_LOG("[DxbcAnalyzer]   (+%d more opcodes, %d total instructions)",
               distinct - 25, hidden);
    }
}

std::atomic<bool> g_didRun{false};
std::chrono::steady_clock::time_point g_installTime = std::chrono::steady_clock::now();

}  // namespace

void Run() {
    bool expected = false;
    if (!g_didRun.compare_exchange_strong(expected, true)) return;

    OD_LOG("[DxbcAnalyzer] Scanning all captured shaders. This sizes the DXBC->SPIR-V "
           "translation work for Phase A.3c.");

    Aggregate vsAgg, psAgg;
    resmirror::ForEachVertexShader(VsVisitor, &vsAgg);
    resmirror::ForEachPixelShader(PsVisitor, &psAgg);

    DumpReport("VS", vsAgg);
    DumpReport("PS", psAgg);

    // Combined opcode union — what the translator must support to handle 100% of shaders.
    Aggregate combined = vsAgg;
    combined.totalShaders += psAgg.totalShaders;
    combined.totalInstructions += psAgg.totalInstructions;
    combined.malformed += psAgg.malformed;
    combined.controlFlowShaders += psAgg.controlFlowShaders;
    for (int i = 0; i < 4; ++i) combined.smCounts[i] += psAgg.smCounts[i];
    for (int i = 0; i < 256; ++i) combined.opcodeCounts[i] += psAgg.opcodeCounts[i];
    combined.highOpcodeCount += psAgg.highOpcodeCount;
    DumpReport("VS+PS combined", combined);

    int distinctOpcodes = 0;
    for (int op = 0; op < 256; ++op) if (combined.opcodeCounts[op] > 0) ++distinctOpcodes;
    OD_LOG("[DxbcAnalyzer] *** Translator coverage target: %d distinct D3D9 opcodes "
           "across %d shaders. ***", distinctOpcodes, combined.totalShaders);
}

void MaybeRun() {
    if (g_didRun.load(std::memory_order_relaxed)) return;
    // Wait until ~60s after install — by then Skyrim has loaded the bulk of
    // its shaders (we observe ~879 VS + 159 PS plateau by ~30s in the log).
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - g_installTime).count();
    if (elapsed >= 60) Run();
}

}
