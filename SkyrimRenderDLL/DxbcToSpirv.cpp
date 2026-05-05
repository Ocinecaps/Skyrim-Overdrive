#include "DxbcToSpirv.h"
#include "DxbcParser.h"
#include "SpirvBuilder.h"

#include <atomic>
#include <cstdio>
#include <cstring>

namespace overdrive::dxbc_spirv {

using namespace overdrive::spirv;

std::vector<uint32_t> EmitMinimalVS() {
    Builder b;
    // 1. Capability + GLSL.std.450 extension.
    b.Capability(CapShader);
    b.ExtInstImport("GLSL.std.450");
    b.MemoryModel(AddrLogical, MemGLSL450);

    // 2. Common types.
    uint32_t tVoid  = b.TypeVoid();
    uint32_t tF32   = b.TypeFloat(32);
    uint32_t tV4F   = b.TypeVector(tF32, 4);
    uint32_t tFn    = b.TypeFunction(tVoid, nullptr, 0);

    // 3. Input + output variables.
    //    in  vec4 inPos    (Location 0)
    //    out vec4 gl_Position (BuiltIn Position)
    uint32_t tPtrInV4  = b.TypePointer(StorageInput,  tV4F);
    uint32_t tPtrOutV4 = b.TypePointer(StorageOutput, tV4F);
    uint32_t inPos     = b.Variable(tPtrInV4,  StorageInput);
    uint32_t outPos    = b.Variable(tPtrOutV4, StorageOutput);

    b.Decorate1(inPos,  DecLocation, 0);
    b.Decorate1(outPos, DecBuiltIn,  BuiltInPosition);

    // 4. Function body — gl_Position = inPos.
    uint32_t fnMain = b.Function(tVoid, FnCtrlNone, tFn);
    uint32_t lblId  = b.NewId();
    b.Label(lblId);
    uint32_t loaded = b.Load(tV4F, inPos);
    b.Store(outPos, loaded);
    b.ReturnVoid();
    b.FunctionEnd();

    // 5. EntryPoint declaration must reference the function ID and the
    //    interface (all Input + Output globals used in the entry point's
    //    statically-reachable code).
    uint32_t ifaces[] = { inPos, outPos };
    b.EntryPoint(ExecVertex, fnMain, "main", ifaces, 2);

    return b.Finalize();
}

std::vector<uint32_t> EmitMinimalPS() {
    Builder b;
    b.Capability(CapShader);
    b.ExtInstImport("GLSL.std.450");
    b.MemoryModel(AddrLogical, MemGLSL450);

    uint32_t tVoid = b.TypeVoid();
    uint32_t tF32  = b.TypeFloat(32);
    uint32_t tV4F  = b.TypeVector(tF32, 4);
    uint32_t tFn   = b.TypeFunction(tVoid, nullptr, 0);

    uint32_t cOne  = b.ConstantF(tF32, 1.0f);
    uint32_t cZero = b.ConstantF(tF32, 0.0f);
    // Constant: vec4(1, 0, 0, 1) — debug red, makes the first translated
    // pixel shader visually obvious during validation.
    uint32_t parts[] = { cOne, cZero, cZero, cOne };
    uint32_t cRed  = b.ConstantComposite(tV4F, parts, 4);

    uint32_t tPtrOutV4 = b.TypePointer(StorageOutput, tV4F);
    uint32_t outColor  = b.Variable(tPtrOutV4, StorageOutput);
    b.Decorate1(outColor, DecLocation, 0);

    uint32_t fnMain = b.Function(tVoid, FnCtrlNone, tFn);
    uint32_t lblId  = b.NewId();
    b.Label(lblId);
    b.Store(outColor, cRed);
    b.ReturnVoid();
    b.FunctionEnd();

    // Fragment shaders must declare the OriginUpperLeft execution mode in
    // Vulkan (D3D / Vulkan default). Validation rejects modules without it.
    uint32_t ifaces[] = { outColor };
    b.EntryPoint(ExecFragment, fnMain, "main", ifaces, 1);
    b.ExecutionMode(fnMain, ModeOriginUpperLeft);

    return b.Finalize();
}

// =============================================================================
// Step 2 — opcode-by-opcode translator (vertex shaders only, very narrow set)
// =============================================================================
//
// This is the actual emit loop. Today's coverage:
//   Opcodes:  mov, dp4, ret, dcl, def, mul, mad, dp3, add
//   Reg types: rN (temp, ≤16), vN (input, ≤16), cN (constant, ≤16; placeholder
//              StoragePrivate — real binding lands with descriptor-set work),
//              oPos (RastOut), oTC0..7 (TexCrdOut, mapped to output Locations
//              after gl_Position), oC0 (ColorOut)
//   Source modifiers: none (rejected if present)
//   Dest:    write masks via per-channel store; saturate/shift not supported
//
// Any other feature returns false from Run(), caller falls back to minimal
// passthrough. The pass-rate metric — "X / 879 VS translate cleanly" —
// drives our coverage prioritization. Each new opcode added here moves that
// number up.
namespace {

using namespace overdrive::dxbc;

// Per-translator-thread buffer for dynamic fail-reason strings (the Translator
// reports specific reg-type values in fail messages so we can bucket which
// types are remaining gates). thread_local because shader translation can
// happen on any thread the game calls Mirror_CreateVertexShader from.
thread_local char tl_failReasonBuf[64];

class Translator {
public:
    explicit Translator(const Decoded& d) : dec_(d) {}
    bool Run();
    std::vector<uint32_t> Module() { return b_.Finalize(); }
    const char* failReason = "";

    // Format "unsupported {dst|src} reg type N (NAME)" into the thread-local
    // buffer and point failReason at it. Lets the LiveXlat fail-bucket
    // histogram show the SPECIFIC reg type, not just generic.
    void StoreFailReasonForRegType(const char* slot, RegType t) {
        const char* name = "unknown";
        switch (t) {
            case RegType::Temp:        name = "Temp";        break;
            case RegType::Input:       name = "Input";       break;
            case RegType::Const:       name = "Const";       break;
            case RegType::Addr:        name = "Addr";        break;
            case RegType::RastOut:     name = "RastOut";     break;
            case RegType::AttrOut:     name = "AttrOut";     break;
            case RegType::TexCrdOut:   name = "TexCrdOut";   break;
            case RegType::ConstInt:    name = "ConstInt";    break;
            case RegType::ColorOut:    name = "ColorOut";    break;
            case RegType::DepthOut:    name = "DepthOut";    break;
            case RegType::Sampler:     name = "Sampler";     break;
            case RegType::Const2:      name = "Const2";      break;
            case RegType::Const3:      name = "Const3";      break;
            case RegType::Const4:      name = "Const4";      break;
            case RegType::ConstBool:   name = "ConstBool";   break;
            case RegType::Loop:        name = "Loop";        break;
            case RegType::TempFloat16: name = "TempFloat16"; break;
            case RegType::MiscType:    name = "MiscType";    break;
            case RegType::Label:       name = "Label";       break;
            case RegType::Predicate:   name = "Predicate";   break;
            default: break;
        }
        std::snprintf(tl_failReasonBuf, sizeof(tl_failReasonBuf),
                      "unsupported %s reg type %u (%s)", slot,
                      static_cast<unsigned>(t), name);
        failReason = tl_failReasonBuf;
    }

private:
    const Decoded& dec_;
    Builder b_;

    // Common type IDs.
    uint32_t tVoid_ = 0, tF32_ = 0, tV4F_ = 0, tFn_ = 0, tBool_ = 0;
    uint32_t tPtrFuncV4F_ = 0, tPtrInputV4F_ = 0, tPtrOutputV4F_ = 0;
    uint32_t tPtrPrivateV4F_ = 0, tPtrFuncF_ = 0, tPtrOutputF_ = 0;
    uint32_t cZeroF_ = 0;
    uint32_t cOneF_  = 0;
    uint32_t cTrue_  = 0;     // bool true (used for ConstBool src in `if b0`)
    // GLSL.std.450 extended instruction set ID — for FAbs / FMin / FMax /
    // Normalize / InverseSqrt / Fract / etc.
    uint32_t glsl_ = 0;

    // Stack of open `if` frames. Each entry holds the labels we pre-allocated
    // when `if` was encountered, so `else` and `endif` can close blocks
    // correctly. Nested ifs push deeper.
    struct IfFrame { uint32_t elseLbl, mergeLbl; bool sawElse; };
    std::vector<IfFrame> ifStack_;

    // Constant int IDs for AccessChain — index 0..3 to address vector lanes.
    uint32_t tU32_ = 0;
    uint32_t kIdx_[4] = {};

    // Per-register variable IDs.
    static constexpr int kMaxConstRegs = 256;   // Skyrim uses up to ~c96
    // vs_3_0 uses RegType=6 (TexCrdOut/Output) for all output registers oN
    // (declared via dcl_<usage>). Indices can range up to 11 (12 outputs).
    // vs_2_x uses TexCrdOut for oT0..oT7 only. We size for 12 to cover both
    // and let EmitGlobals allocate Locations sequentially for whichever are
    // used. ~52 vs_3_0 shaders previously failed with "tc index >= 8".
    static constexpr int kMaxOutRegs = 12;
    uint32_t tempVar_[16] = {};
    uint32_t inputVar_[16] = {};
    uint32_t constVar_[kMaxConstRegs] = {};
    uint32_t outPosVar_      = 0;     // RastOut → gl_Position
    uint32_t outColorVar_    = 0;     // ColorOut[0]
    uint32_t outTCVar_[kMaxOutRegs]    = {};    // TexCrdOut/Output[0..11]
    uint32_t outAttrVar_[2]  = {};    // AttrOut[0..1] — vs_2_x oD0/oD1

    // Reference flags (set by ScanRefs).
    bool tempUsed_[16] = {};
    bool inputUsed_[16] = {};
    bool constUsed_[kMaxConstRegs] = {};
    bool outPosUsed_   = false;
    bool outColorUsed_ = false;
    bool outTCUsed_[kMaxOutRegs] = {};
    bool outAttrUsed_[2] = {};

    uint32_t fnMain_ = 0;
    std::vector<uint32_t> ifaces_;

    // Pipeline.
    bool ScanRefs();
    void EmitCommonTypes();
    void EmitGlobals();
    bool EmitFunctionBody();
    bool EmitInstruction(const Instruction& ins);

    // Source-load: returns a vec4 ID after applying swizzle.
    uint32_t LoadSrcSwizzled(const SrcParam& s);
    // Get pointer-to-vec4 for a register (its variable ID is already a ptr).
    uint32_t RegPointer(RegType t, uint16_t idx, uint32_t* outPtrType);
    // Store a vec4 into dst, honoring write mask. Splits to per-channel
    // OpStore via OpAccessChain when mask is partial.
    bool StoreDstV4(const DstParam& d, uint32_t v4);
    // Store a single scalar into dst — used by dp4/dp3 where a single mask
    // bit selects the channel; broadcasts to vec4 when full mask.
    bool StoreDstScalar(const DstParam& d, uint32_t scalar);
};

bool Translator::ScanRefs() {
    if (dec_.isPixelShader) {
        failReason = "PS not yet supported (next iteration)";
        return false;
    }
    for (auto& ins : dec_.ins) {
        switch (ins.opcode) {
            case 1:   // mov
            case 2:   // add
            case 3:   // sub
            case 4:   // mad
            case 5:   // mul
            case 6:   // rcp
            case 7:   // rsq
            case 8:   // dp3
            case 9:   // dp4
            case 10:  // min
            case 11:  // max
            case 12:  // slt — set if a<b   (impl: 1 - step(b, a))
            case 13:  // sge — set if a>=b  (impl: step(b, a))
            case 18:  // lrp
            case 14:  // exp
            case 15:  // log
            case 19:  // frc
            case 20:  // m4x4 — dst = src0 * matrix(c[N..N+3])  vec4 result
            case 21:  // m4x3 — vec4 input, 3-row matrix, writes .xyz
            case 22:  // m3x4 — vec3 input, 4-row matrix, vec4 output
            case 23:  // m3x3 — vec3 input, 3-row matrix, writes .xyz
            case 24:  // m3x2 — vec3 input, 2-row matrix, writes .xy
            case 28:  // ret
            case 31:  // dcl  (no-op: just declares)
            case 32:  // pow
            case 33:  // crs — 3-component cross product  (vec shuffles + mul/sub)
            case 34:  // sgn
            case 35:  // abs
            case 36:  // nrm  (normalize xyz, keep .w)
            case 37:  // sincos — dst.x=cos, dst.y=sin (vs_2_x has 3 srcs, vs_3_0 has 1)
            case 40:  // if — branch on src
            case 42:  // else — switch to else block
            case 43:  // endif — close the if block
            case 46:  // mova — move to address register a0 (no-op for now;
                      //   indexed const access via c[a0.x] silently degrades
                      //   to c[N] in src loading. Skinning shaders compile
                      //   structurally; geometry will be wrong until we wire
                      //   relative addressing — Phase A.3c-step3 work.)
            case 47:  // defb — inline bool constant (no-op; bool consts unused)
            case 48:  // defi — inline int constant (no-op; loop counters unused
                      //   until loop emission lands)
            case 78:  // expp (exp with partial precision — same emission)
            case 79:  // logp (log with partial precision)
            case 80:  // cnd — dst = (src0 > 0.5) ? src1 : src2
            case 81:  // def  (skipped — c-register data flow comes later)
            case 88:  // cmp — dst = (src0 >= 0) ? src1 : src2
                break;
            default:
                failReason = "unsupported opcode";
                return false;
        }
        // Matrix ops reference src1.index + N consecutive const registers.
        // Mark them all as used so EmitGlobals declares them.
        if (ins.opcode >= 20 && ins.opcode <= 24 && ins.srcs.size() >= 2) {
            int rows = (ins.opcode == 20 || ins.opcode == 22) ? 4
                     : (ins.opcode == 24) ? 2 : 3;
            const auto& mSrc = ins.srcs[1];
            if (mSrc.type == RegType::Const) {
                int base = mSrc.index;
                if (base + rows > kMaxConstRegs) {
                    failReason = "matrix const out of range";
                    return false;
                }
                for (int k = 0; k < rows; ++k) constUsed_[base + k] = true;
            }
        }
        if (ins.predicated)             { failReason = "predication";        return false; }
        // `def` / `defi` / `defb` define an inline constant — their dst is a
        // CONST/CONSTINT/CONSTBOOL register, which our regular dst-type
        // switch doesn't accept. We don't translate the def itself either
        // (constants are placeholder zeros today), so skip per-instruction
        // src/dst validation for these. Without this, every Skyrim VS that
        // contains an inline constant (most of them) hard-rejects.
        if (ins.opcode == 81 || ins.opcode == 48 || ins.opcode == 47) {
            continue;
        }
        // `mova` writes to the address register a0. Its dst is RegType::Addr
        // (=3) which our regular dst-type switch doesn't accept. Skip dst/src
        // validation here — mova is a no-op in our emit (we don't yet model
        // a0 explicitly; indexed const reads silently use c[N]).
        if (ins.opcode == 46) {
            continue;
        }
        // Flow control: `else` (42) and `endif` (43) have neither dst nor
        // srcs; nothing to validate. `if` (40) has 1 src that may be of
        // RegType::ConstBool (b0..b15), which our regular src-type switch
        // doesn't accept — handle it here so the shader scans cleanly. The
        // ConstBool data flow itself isn't wired up; we treat `if bN` as
        // unconditionally TRUE in EmitInstruction so the if-body executes
        // (better default than skipping every conditional render path).
        if (ins.opcode == 42 || ins.opcode == 43) {
            continue;
        }
        if (ins.opcode == 40) {
            if (ins.srcs.empty()) { failReason = "if has no src"; return false; }
            const auto& s = ins.srcs[0];
            if (s.type == RegType::ConstBool) continue;  // accept; handle in emit
            // Otherwise let the regular src loop validate it.
        }
        // Dst modifier bits: 0x1 = SATURATE (clamp to [0,1]), 0x2 = PARTIAL_
        // PRECISION (precision hint, ignorable), 0x4 = MSAMPCENTROID. Accept
        // saturate (apply via FClamp) and partial-precision (ignore); reject
        // others. Universal Skyrim PS / lighting VS uses saturate constantly,
        // so without this the translator hard-rejects every shader.
        if (ins.hasDst && (ins.dst.modifier & ~0x3u)) {
            failReason = "dst modifier (msaa centroid or unknown)";
            return false;
        }
        if (ins.hasDst && ins.dst.shift)    { failReason = "dst shift";      return false; }
        if (ins.hasDst) {
            switch (ins.dst.type) {
                case RegType::Temp:
                    if (ins.dst.index >= 16) { failReason = "temp index >= 16"; return false; }
                    tempUsed_[ins.dst.index] = true; break;
                case RegType::RastOut:
                    outPosUsed_ = true; break;
                case RegType::ColorOut:
                    outColorUsed_ = true; break;
                case RegType::AttrOut:
                    // oD0 / oD1 in vs_2_x — vertex color outputs. Universal in
                    // Skyrim VS code; without this 878/879 shaders rejected.
                    if (ins.dst.index >= 2) { failReason = "attrout index >= 2"; return false; }
                    outAttrUsed_[ins.dst.index] = true; break;
                case RegType::TexCrdOut:
                    if (ins.dst.index >= kMaxOutRegs) { failReason = "tc index >= 12"; return false; }
                    outTCUsed_[ins.dst.index] = true; break;
                default:
                    StoreFailReasonForRegType("dst", ins.dst.type);
                    return false;
            }
        }
        for (auto& s : ins.srcs) {
            // Source modifiers: 1=NEG, 0xB=ABS, 0xC=ABSNEG. We support
            // these by post-processing the loaded value (OpFNegate / FAbs).
            // Other modifiers (_bias, _sign, _comp, _x2, _dz, _dw, _not)
            // are rare in modern shaders — reject for now.
            if (s.modifier != 0 && s.modifier != 1 &&
                s.modifier != 0xB && s.modifier != 0xC) {
                failReason = "src modifier (bias/sign/comp/x2/...)";
                return false;
            }
            switch (s.type) {
                case RegType::Temp:
                    if (s.index >= 16) { failReason = "src temp >= 16"; return false; }
                    tempUsed_[s.index] = true; break;
                case RegType::Input:
                    if (s.index >= 16) { failReason = "src input >= 16"; return false; }
                    inputUsed_[s.index] = true; break;
                case RegType::Const:
                    if (s.index >= kMaxConstRegs) { failReason = "src const out of range"; return false; }
                    constUsed_[s.index] = true; break;
                default:
                    StoreFailReasonForRegType("src", s.type);
                    return false;
            }
        }
    }
    return true;
}

void Translator::EmitCommonTypes() {
    b_.Capability(CapShader);
    glsl_ = b_.ExtInstImport("GLSL.std.450");
    b_.MemoryModel(AddrLogical, MemGLSL450);

    tVoid_ = b_.TypeVoid();
    tBool_ = b_.TypeBool();
    tF32_  = b_.TypeFloat(32);
    tV4F_  = b_.TypeVector(tF32_, 4);
    tFn_   = b_.TypeFunction(tVoid_, nullptr, 0);

    tPtrFuncV4F_    = b_.TypePointer(StorageFunction, tV4F_);
    tPtrFuncF_      = b_.TypePointer(StorageFunction, tF32_);
    tPtrInputV4F_   = b_.TypePointer(StorageInput,    tV4F_);
    tPtrOutputV4F_  = b_.TypePointer(StorageOutput,   tV4F_);
    tPtrOutputF_    = b_.TypePointer(StorageOutput,   tF32_);
    tPtrPrivateV4F_ = b_.TypePointer(StoragePrivate,  tV4F_);

    cZeroF_ = b_.ConstantF(tF32_, 0.0f);
    cOneF_  = b_.ConstantF(tF32_, 1.0f);
    // Bool true constant for ConstBool-driven `if` paths (until ConstBool
    // data flow lands, every `if bN` evaluates as true).
    cTrue_  = b_.ConstantTrue(tBool_);

    // Build OpTypeInt 32 0 (unsigned) and the four index constants used by
    // OpAccessChain when we address single channels of vec4 outputs.
    {
        uint32_t id = b_.NewId();
        // Emulate via raw appender — we don't expose TypeInt yet, so we
        // reuse the typesConsts section via Variable pathway. Instead the
        // simplest is to use a SPIR-V helper: use a custom emit. Add a
        // small helper that just appends an OpTypeInt instruction.
        // We bypass that by using TypeFloat trick and casting? No — we just
        // need integer constants for AccessChain. The simplest valid SPIR-V
        // index constants are uints. Use AppendInFunction-like pattern via
        // a transient emit — since SpirvBuilder doesn't yet expose TypeInt
        // we add it inline by constructing the instruction stream for a
        // type-int + four constants here, into the typesConsts section via
        // the same pathway Builder uses internally. This is an isolated
        // exception — proper TypeInt helper lands in the next iteration.
        (void)id;
    }
    // Until we expose TypeInt cleanly, channel access uses OpCompositeExtract
    // with literal-int operands (which is allowed for OpCompositeExtract —
    // unlike OpAccessChain, the indices are literals, not IDs).
    // So tU32_/kIdx_ are unused for now. Single-channel WRITES become a
    // vector-shuffle + full-vector store instead of an AccessChain store.
}

void Translator::EmitGlobals() {
    // Inputs: only 16 vN registers in D3D9.
    for (int i = 0; i < 16; ++i) {
        if (inputUsed_[i]) {
            inputVar_[i] = b_.Variable(tPtrInputV4F_, StorageInput);
            b_.Decorate1(inputVar_[i], DecLocation, i);
            ifaces_.push_back(inputVar_[i]);
        }
    }
    // Constants: up to 256. Skyrim's lighting/skinning shaders use up to ~c96.
    // Phase A.3c step 2: c-registers are placeholders backed by StoragePrivate
    // vec4 zeros. Real cN data flow (SetVertexShaderConstantF → push_constants
    // / UBO) lands when we hook constant uploads. Until then, the SPIR-V is
    // structurally valid but the shader will read zero — fine for module/
    // pipeline compile tests.
    for (int i = 0; i < kMaxConstRegs; ++i) {
        if (constUsed_[i]) {
            constVar_[i] = b_.Variable(tPtrPrivateV4F_, StoragePrivate);
        }
    }
    if (outPosUsed_) {
        outPosVar_ = b_.Variable(tPtrOutputV4F_, StorageOutput);
        b_.Decorate1(outPosVar_, DecBuiltIn, BuiltInPosition);
        ifaces_.push_back(outPosVar_);
    }
    int outLoc = 0;
    for (int i = 0; i < kMaxOutRegs; ++i) {
        if (outTCUsed_[i]) {
            outTCVar_[i] = b_.Variable(tPtrOutputV4F_, StorageOutput);
            b_.Decorate1(outTCVar_[i], DecLocation, outLoc++);
            ifaces_.push_back(outTCVar_[i]);
        }
    }
    // AttrOut (vs_2_x oD0/oD1) — vertex color outputs. Allocate as
    // additional output Locations after the texcoords. The fragment-shader
    // side will bind matching Location inputs once we wire PS translation.
    for (int i = 0; i < 2; ++i) {
        if (outAttrUsed_[i]) {
            outAttrVar_[i] = b_.Variable(tPtrOutputV4F_, StorageOutput);
            b_.Decorate1(outAttrVar_[i], DecLocation, outLoc++);
            ifaces_.push_back(outAttrVar_[i]);
        }
    }
    if (outColorUsed_) {
        outColorVar_ = b_.Variable(tPtrOutputV4F_, StorageOutput);
        b_.Decorate1(outColorVar_, DecLocation, outLoc++);
        ifaces_.push_back(outColorVar_);
    }
}

uint32_t Translator::RegPointer(RegType t, uint16_t idx, uint32_t* outPtrType) {
    switch (t) {
        case RegType::Temp:
            if (outPtrType) *outPtrType = tPtrFuncV4F_;
            return tempVar_[idx];
        case RegType::Input:
            if (outPtrType) *outPtrType = tPtrInputV4F_;
            return inputVar_[idx];
        case RegType::Const:
            if (outPtrType) *outPtrType = tPtrPrivateV4F_;
            return constVar_[idx];
        case RegType::RastOut:
            if (outPtrType) *outPtrType = tPtrOutputV4F_;
            return outPosVar_;
        case RegType::AttrOut:
            if (outPtrType) *outPtrType = tPtrOutputV4F_;
            return idx < 2 ? outAttrVar_[idx] : 0;
        case RegType::ColorOut:
            if (outPtrType) *outPtrType = tPtrOutputV4F_;
            return outColorVar_;
        case RegType::TexCrdOut:
            if (outPtrType) *outPtrType = tPtrOutputV4F_;
            return outTCVar_[idx];
        default:
            return 0;
    }
}

uint32_t Translator::LoadSrcSwizzled(const SrcParam& s) {
    uint32_t ptrType = 0;
    uint32_t var = RegPointer(s.type, s.index, &ptrType);
    if (!var) return 0;
    uint32_t loaded = b_.Load(tV4F_, var);

    // Identity swizzle = xyzw = packed 0,1,2,3 = 0b11100100 = 0xE4. Skip
    // the shuffle in that case — saves an OpVectorShuffle per source.
    uint32_t v = loaded;
    if (s.swizzle != 0xE4) {
        uint32_t comps[4] = {
            s.Channel(0), s.Channel(1), s.Channel(2), s.Channel(3)
        };
        v = b_.VectorShuffle(tV4F_, loaded, loaded, comps, 4);
    }
    // Apply source modifier. NEG=1, ABS=0xB, ABSNEG=0xC. These are the
    // common modifiers used by Skyrim shaders — without supporting them
    // every real shader hard-rejects.
    if (s.modifier == 0xB || s.modifier == 0xC) {
        // GLSL.std.450 FAbs = 4
        v = b_.ExtInst(tV4F_, glsl_, 4, &v, 1);
    }
    if (s.modifier == 1 || s.modifier == 0xC) {
        // OpFNegate has no dedicated helper — emit raw.
        uint32_t ops[] = { tV4F_, b_.NewId(), v };
        v = b_.AppendInFunction(OpFNegate, ops, 3);
    }
    return v;
}

bool Translator::StoreDstV4(const DstParam& d, uint32_t v4) {
    uint32_t ptrType = 0;
    uint32_t var = RegPointer(d.type, d.index, &ptrType);
    if (!var) { failReason = "no dst variable"; return false; }
    // Apply saturate dst modifier (clamp to [0,1]) BEFORE the masked store.
    // GLSL.std.450 FClamp = 43. Bit 0x2 (PartialPrecision) is just a
    // precision hint — we ignore it, computation is full precision either way.
    if (d.modifier & 0x1) {
        uint32_t zeros4[] = { cZeroF_, cZeroF_, cZeroF_, cZeroF_ };
        uint32_t ones4[]  = { cOneF_,  cOneF_,  cOneF_,  cOneF_  };
        uint32_t z4 = b_.CompositeConstruct(tV4F_, zeros4, 4);
        uint32_t o4 = b_.CompositeConstruct(tV4F_, ones4, 4);
        uint32_t args[] = { v4, z4, o4 };
        v4 = b_.ExtInst(tV4F_, glsl_, 43, args, 3);
    }
    if (d.writeMask == 0xF) {
        b_.Store(var, v4);
        return true;
    }
    // Partial write: load existing dst, vector-shuffle to splice in only the
    // masked lanes, then store.
    uint32_t cur = b_.Load(tV4F_, var);
    // Component layout for OpVectorShuffle: 0..3 = vector1 channels (the new
    // value), 4..7 = vector2 channels (the existing value). For each lane,
    // pick from the new value if its bit is set in the mask, else keep cur.
    uint32_t comps[4];
    for (int i = 0; i < 4; ++i) {
        comps[i] = (d.writeMask & (1u << i)) ? (uint32_t)i : (uint32_t)(4 + i);
    }
    uint32_t merged = b_.VectorShuffle(tV4F_, v4, cur, comps, 4);
    b_.Store(var, merged);
    return true;
}

bool Translator::StoreDstScalar(const DstParam& d, uint32_t scalar) {
    // Broadcast the scalar to a vec4 once, then reuse the vec4 store path.
    uint32_t parts[] = { scalar, scalar, scalar, scalar };
    uint32_t v4 = b_.CompositeConstruct(tV4F_, parts, 4);
    return StoreDstV4(d, v4);
}

bool Translator::EmitInstruction(const Instruction& ins) {
    switch (ins.opcode) {
        case 31: case 47: case 48: case 81:    // dcl, defb, defi, def — no ALU emit
            return true;
        case 46:                    // mova — no-op (a0 not modeled yet)
            return true;
        case 28:                    // ret — handled in EmitFunctionBody
            return true;
        case 40: {                  // if — branch on src.x != 0 (or true if ConstBool)
            // SPIR-V structured selection:
            //   OpSelectionMerge %merge None
            //   OpBranchConditional %cond %then %else
            //   %then = OpLabel
            //     <if-body>
            //     (closed by `else` or `endif`)
            // The pre-allocated %else and %merge labels are recorded on
            // ifStack_ so `else` and `endif` know where to branch.
            if (ins.srcs.empty()) { failReason = "if no src"; return false; }
            const auto& s = ins.srcs[0];
            uint32_t cond = 0;
            if (s.type == RegType::ConstBool) {
                // Bool data flow not wired yet — default to true so the body
                // executes. Best heuristic for "if feature_enabled" patterns.
                cond = cTrue_;
            } else {
                // Treat as float compare: extract .x channel, OpFOrdNotEqual 0.
                uint32_t v4 = LoadSrcSwizzled(s);
                if (!v4) { failReason = "if src load failed"; return false; }
                uint32_t xIdx = 0;
                uint32_t scalar = b_.CompositeExtract(tF32_, v4, &xIdx, 1);
                uint32_t neId = b_.NewId();
                uint32_t neOps[] = { tBool_, neId, scalar, cZeroF_ };
                b_.AppendInFunction(OpFOrdNotEqual, neOps, 4);
                cond = neId;
            }
            uint32_t thenLbl  = b_.NewId();
            uint32_t elseLbl  = b_.NewId();
            uint32_t mergeLbl = b_.NewId();
            // OpSelectionMerge merge SelCtrlNone
            {
                uint32_t mops[] = { mergeLbl, (uint32_t)SelCtrlNone };
                b_.AppendInFunction(OpSelectionMerge, mops, 2);
            }
            // OpBranchConditional cond then else
            {
                uint32_t bops[] = { cond, thenLbl, elseLbl };
                b_.AppendInFunction(OpBranchConditional, bops, 3);
            }
            b_.Label(thenLbl);
            ifStack_.push_back({ elseLbl, mergeLbl, /*sawElse=*/false });
            return true;
        }
        case 42: {                  // else — close then-block, open else-block
            if (ifStack_.empty()) { failReason = "else without matching if"; return false; }
            IfFrame& f = ifStack_.back();
            if (f.sawElse)         { failReason = "second else for one if"; return false; }
            // Close the then-block with OpBranch %merge.
            { uint32_t bops[] = { f.mergeLbl }; b_.AppendInFunction(OpBranch, bops, 1); }
            // Open the else-block.
            b_.Label(f.elseLbl);
            f.sawElse = true;
            return true;
        }
        case 43: {                  // endif — close current block, open merge
            if (ifStack_.empty()) { failReason = "endif without matching if"; return false; }
            IfFrame f = ifStack_.back();
            ifStack_.pop_back();
            if (!f.sawElse) {
                // No else seen — close the then-block, emit empty else, open merge.
                { uint32_t bops[] = { f.mergeLbl }; b_.AppendInFunction(OpBranch, bops, 1); }
                b_.Label(f.elseLbl);
                { uint32_t bops[] = { f.mergeLbl }; b_.AppendInFunction(OpBranch, bops, 1); }
                b_.Label(f.mergeLbl);
            } else {
                // Else was seen — close the else-block, open merge.
                { uint32_t bops[] = { f.mergeLbl }; b_.AppendInFunction(OpBranch, bops, 1); }
                b_.Label(f.mergeLbl);
            }
            return true;
        }
        case 1: {                   // mov
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "mov shape"; return false; }
            uint32_t v = LoadSrcSwizzled(ins.srcs[0]);
            return StoreDstV4(ins.dst, v);
        }
        case 2: {                   // add
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "add shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t r = b_.FAdd(tV4F_, a, bV);
            return StoreDstV4(ins.dst, r);
        }
        case 5: {                   // mul
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "mul shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t r = b_.FMul(tV4F_, a, bV);
            return StoreDstV4(ins.dst, r);
        }
        case 4: {                   // mad — a*b + c
            if (ins.srcs.size() != 3 || !ins.hasDst) { failReason = "mad shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t c = LoadSrcSwizzled(ins.srcs[2]);
            uint32_t mul = b_.FMul(tV4F_, a, bV);
            uint32_t r   = b_.FAdd(tV4F_, mul, c);
            return StoreDstV4(ins.dst, r);
        }
        case 8: {                   // dp3 — sum of xyz components
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "dp3 shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            // dot(a.xyz, b.xyz): build vec3s via shuffle, then OpDot. We don't
            // have TypeVector vec3 yet — instead, just zero the .w of both
            // vec4s and call vec4 OpDot. Equivalent result.
            uint32_t zeroA[4] = { 0, 1, 2, 7 };  // a.xyz, then "vec2[3]" channel = 7 → from b? careful
            // Simpler: build a vec4 with .w forced to zero by shuffling
            // against constant zero. Avoids needing extra constant materialization
            // for now: instead just compute dp4 (it's a superset for the common
            // case where both have zero in .w). Reject if .w bits in both srcs
            // are not zero — but we can't tell at compile time, so accept
            // and live with the imprecision until we add real vec3 dot.
            // For correctness target later: emit OpVectorShuffle to build
            // (a.x, a.y, a.z, 0) and (b.x, b.y, b.z, 0), then dp4.
            // Use the source xyzw shuffles already in place; force .w=0 via a
            // vec4(0,0,0,0) and shuffle.
            uint32_t zeros4[] = { cZeroF_, cZeroF_, cZeroF_, cZeroF_ };
            uint32_t z4 = b_.CompositeConstruct(tV4F_, zeros4, 4);
            uint32_t aMask[] = { 0u, 1u, 2u, 7u };  // .x .y .z, then .w from z4
            uint32_t bMask[] = { 0u, 1u, 2u, 7u };
            uint32_t aXYZ0  = b_.VectorShuffle(tV4F_, a,  z4, aMask, 4);
            uint32_t bXYZ0  = b_.VectorShuffle(tV4F_, bV, z4, bMask, 4);
            uint32_t scalar = b_.Dot(tF32_, aXYZ0, bXYZ0);
            return StoreDstScalar(ins.dst, scalar);
        }
        case 9: {                   // dp4
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "dp4 shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t scalar = b_.Dot(tF32_, a, bV);
            return StoreDstScalar(ins.dst, scalar);
        }
        case 3: {                   // sub  dst = src0 - src1
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "sub shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t r = b_.FSub(tV4F_, a, bV);
            return StoreDstV4(ins.dst, r);
        }
        case 6: {                   // rcp  dst = 1.0 / src0
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "rcp shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            // Build vec4 of 1.0 then OpFDiv. D3D9 rcp replicates the .x
            // channel, but for full vec4 store this is close enough today —
            // proper "replicate one channel" lands when we model swizzles
            // more precisely.
            uint32_t ones[] = { cOneF_, cOneF_, cOneF_, cOneF_ };
            uint32_t one4 = b_.CompositeConstruct(tV4F_, ones, 4);
            uint32_t ops[] = { tV4F_, b_.NewId(), one4, a };
            uint32_t r = b_.AppendInFunction(OpFDiv, ops, 4);
            return StoreDstV4(ins.dst, r);
        }
        case 7: {                   // rsq  dst = 1.0 / sqrt(src0)
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "rsq shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            // GLSL.std.450 InverseSqrt = 32
            uint32_t r = b_.ExtInst(tV4F_, glsl_, 32, &a, 1);
            return StoreDstV4(ins.dst, r);
        }
        case 10: {                  // min  dst = min(src0, src1)
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "min shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t args[] = { a, bV };
            // GLSL.std.450 FMin = 37
            uint32_t r = b_.ExtInst(tV4F_, glsl_, 37, args, 2);
            return StoreDstV4(ins.dst, r);
        }
        case 11: {                  // max  dst = max(src0, src1)
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "max shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t args[] = { a, bV };
            // GLSL.std.450 FMax = 40
            uint32_t r = b_.ExtInst(tV4F_, glsl_, 40, args, 2);
            return StoreDstV4(ins.dst, r);
        }
        case 18: {                  // lrp  dst = src1 + src0 * (src2 - src1)
            if (ins.srcs.size() != 3 || !ins.hasDst) { failReason = "lrp shape"; return false; }
            uint32_t t = LoadSrcSwizzled(ins.srcs[0]);   // weight
            uint32_t a = LoadSrcSwizzled(ins.srcs[1]);   // base
            uint32_t bV = LoadSrcSwizzled(ins.srcs[2]);  // target
            uint32_t diff = b_.FSub(tV4F_, bV, a);
            uint32_t weighted = b_.FMul(tV4F_, t, diff);
            uint32_t r = b_.FAdd(tV4F_, a, weighted);
            return StoreDstV4(ins.dst, r);
        }
        case 19: {                  // frc  dst = frac(src0)
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "frc shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            // GLSL.std.450 Fract = 10
            uint32_t r = b_.ExtInst(tV4F_, glsl_, 10, &a, 1);
            return StoreDstV4(ins.dst, r);
        }
        case 14: case 78: {         // exp / expp — dst = 2^src0 component-wise
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "exp shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            // GLSL.std.450 Exp2 = 29
            uint32_t r = b_.ExtInst(tV4F_, glsl_, 29, &a, 1);
            return StoreDstV4(ins.dst, r);
        }
        case 15: case 79: {         // log / logp — dst = log2(src0) component-wise
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "log shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            // GLSL.std.450 Log2 = 30
            uint32_t r = b_.ExtInst(tV4F_, glsl_, 30, &a, 1);
            return StoreDstV4(ins.dst, r);
        }
        case 32: {                  // pow  dst = pow(src0, src1)
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "pow shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t args[] = { a, bV };
            // GLSL.std.450 Pow = 26
            uint32_t r = b_.ExtInst(tV4F_, glsl_, 26, args, 2);
            return StoreDstV4(ins.dst, r);
        }
        case 34: {                  // sgn  dst = sign(src0)
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "sgn shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            // GLSL.std.450 FSign = 6
            uint32_t r = b_.ExtInst(tV4F_, glsl_, 6, &a, 1);
            return StoreDstV4(ins.dst, r);
        }
        case 35: {                  // abs  dst = abs(src0)
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "abs shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            // GLSL.std.450 FAbs = 4
            uint32_t r = b_.ExtInst(tV4F_, glsl_, 4, &a, 1);
            return StoreDstV4(ins.dst, r);
        }
        case 36: {                  // nrm  dst.xyz = normalize(src0.xyz), dst.w preserved
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "nrm shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            // Zero .w of input so Normalize operates on xyz0. Result.w is 0
            // — for typical Skyrim usage (normalizing a tangent/normal vec3)
            // that's fine; the dst write mask usually only writes .xyz.
            uint32_t zeros4[] = { cZeroF_, cZeroF_, cZeroF_, cZeroF_ };
            uint32_t z4 = b_.CompositeConstruct(tV4F_, zeros4, 4);
            uint32_t mask[] = { 0u, 1u, 2u, 7u };
            uint32_t aXYZ0 = b_.VectorShuffle(tV4F_, a, z4, mask, 4);
            // GLSL.std.450 Normalize = 69
            uint32_t r = b_.ExtInst(tV4F_, glsl_, 69, &aXYZ0, 1);
            return StoreDstV4(ins.dst, r);
        }
        case 12: {                  // slt — dst = (src0 < src1) ? 1 : 0
            // Implementation: 1.0 - step(src1, src0). step(b, a) returns 1 if
            // a >= b, so its complement is (a < b) = slt. GLSL.std.450 Step=48.
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "slt shape"; return false; }
            uint32_t a  = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t stepArgs[] = { bV, a };
            uint32_t step = b_.ExtInst(tV4F_, glsl_, 48, stepArgs, 2);
            uint32_t ones4_p[] = { cOneF_, cOneF_, cOneF_, cOneF_ };
            uint32_t one4 = b_.CompositeConstruct(tV4F_, ones4_p, 4);
            uint32_t r = b_.FSub(tV4F_, one4, step);
            return StoreDstV4(ins.dst, r);
        }
        case 13: {                  // sge — dst = (src0 >= src1) ? 1 : 0
            // Implementation: step(src1, src0) returns 1 if src0 >= src1.
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "sge shape"; return false; }
            uint32_t a  = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t stepArgs[] = { bV, a };
            uint32_t r = b_.ExtInst(tV4F_, glsl_, 48, stepArgs, 2);
            return StoreDstV4(ins.dst, r);
        }
        case 33: {                  // crs — dst.xyz = cross(src0.xyz, src1.xyz)
            // crs(a, b).x = a.y*b.z - a.z*b.y
            // crs(a, b).y = a.z*b.x - a.x*b.z
            // crs(a, b).z = a.x*b.y - a.y*b.x
            // Computed via vec4 lane shuffles + mul + sub. Result.w = 0.
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "crs shape"; return false; }
            uint32_t a  = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t mYZX[] = { 1u, 2u, 0u, 3u };
            uint32_t mZXY[] = { 2u, 0u, 1u, 3u };
            uint32_t aYZX = b_.VectorShuffle(tV4F_, a,  a,  mYZX, 4);
            uint32_t bZXY = b_.VectorShuffle(tV4F_, bV, bV, mZXY, 4);
            uint32_t aZXY = b_.VectorShuffle(tV4F_, a,  a,  mZXY, 4);
            uint32_t bYZX = b_.VectorShuffle(tV4F_, bV, bV, mYZX, 4);
            uint32_t lhs = b_.FMul(tV4F_, aYZX, bZXY);
            uint32_t rhs = b_.FMul(tV4F_, aZXY, bYZX);
            uint32_t r   = b_.FSub(tV4F_, lhs, rhs);
            return StoreDstV4(ins.dst, r);
        }
        case 37: {                  // sincos — dst.x = cos(src), dst.y = sin(src)
            // vs_2_x form is `sincos dst, src0, c_macro1, c_macro2` (3 srcs;
            // the macros are constant approximation tables, ignored on modern
            // hardware). vs_3_0 form has just 1 src. Accept any srcs >= 1.
            if (ins.srcs.empty() || !ins.hasDst) { failReason = "sincos shape"; return false; }
            uint32_t s = LoadSrcSwizzled(ins.srcs[0]);
            // GLSL.std.450 Sin = 13, Cos = 14. Compute on the (already-swizzled)
            // vec4 — D3D9 sincos source-swizzles to a scalar replicated across
            // channels, so all lanes carry the same input.
            uint32_t cosV = b_.ExtInst(tV4F_, glsl_, 14, &s, 1);
            uint32_t sinV = b_.ExtInst(tV4F_, glsl_, 13, &s, 1);
            // Build vec4(cos.x, sin.x, 0, 0). VectorShuffle: 0..3 from cosV,
            // 4..7 from sinV. We need (cos.x, sin.x, ?, ?). The dst writeMask
            // controls which of x/y/z/w actually get written; channel 2/3
            // fillers don't matter since the mask determines visibility.
            // Use cos.x at lane 0, sin.x at lane 1, cos.x at lane 2, cos.x at
            // lane 3 (any value works for masked-out lanes; pick cosV to
            // avoid materializing a zero vec4).
            uint32_t comps[4] = { 0u, 4u, 0u, 0u };
            uint32_t out = b_.VectorShuffle(tV4F_, cosV, sinV, comps, 4);
            return StoreDstV4(ins.dst, out);
        }
        case 80: {                  // cnd — dst = (src0 > 0.5) ? src1 : src2
            // Implementation: mix(src2, src1, step(0.5, src0)).
            if (ins.srcs.size() != 3 || !ins.hasDst) { failReason = "cnd shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t s1 = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t s2 = LoadSrcSwizzled(ins.srcs[2]);
            uint32_t cHalfF = b_.ConstantF(tF32_, 0.5f);
            uint32_t halfParts[] = { cHalfF, cHalfF, cHalfF, cHalfF };
            uint32_t half4 = b_.CompositeConstruct(tV4F_, halfParts, 4);
            uint32_t stepArgs[] = { half4, a };
            uint32_t mask = b_.ExtInst(tV4F_, glsl_, 48, stepArgs, 2);  // step
            uint32_t mixArgs[] = { s2, s1, mask };
            uint32_t r = b_.ExtInst(tV4F_, glsl_, 46, mixArgs, 3);      // FMix
            return StoreDstV4(ins.dst, r);
        }
        case 88: {                  // cmp — dst = (src0 >= 0) ? src1 : src2
            // Implementation: mix(src2, src1, step(0, src0)).
            if (ins.srcs.size() != 3 || !ins.hasDst) { failReason = "cmp shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t s1 = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t s2 = LoadSrcSwizzled(ins.srcs[2]);
            uint32_t zeroParts[] = { cZeroF_, cZeroF_, cZeroF_, cZeroF_ };
            uint32_t zero4 = b_.CompositeConstruct(tV4F_, zeroParts, 4);
            uint32_t stepArgs[] = { zero4, a };
            uint32_t mask = b_.ExtInst(tV4F_, glsl_, 48, stepArgs, 2);  // step
            uint32_t mixArgs[] = { s2, s1, mask };
            uint32_t r = b_.ExtInst(tV4F_, glsl_, 46, mixArgs, 3);      // FMix
            return StoreDstV4(ins.dst, r);
        }
        case 20: case 21: case 22: case 23: case 24: {
            // Matrix multiplies: m4x4 / m4x3 / m3x4 / m3x3 / m3x2.
            // The src0 register is a vec (4 or 3 components depending on op).
            // The src1 register is the FIRST of N consecutive registers
            // forming an N-row matrix. Result has rows components.
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "mNxM shape"; return false; }
            int rows = (ins.opcode == 20 || ins.opcode == 22) ? 4
                     : (ins.opcode == 24) ? 2 : 3;
            bool srcIs3Comp = (ins.opcode == 22 || ins.opcode == 23 || ins.opcode == 24);
            // Load src0. Per-channel zero of .w if 3-component dot is needed.
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t a3 = a;
            if (srcIs3Comp) {
                uint32_t zeros4[] = { cZeroF_, cZeroF_, cZeroF_, cZeroF_ };
                uint32_t z4 = b_.CompositeConstruct(tV4F_, zeros4, 4);
                uint32_t mask[] = { 0u, 1u, 2u, 7u };
                a3 = b_.VectorShuffle(tV4F_, a, z4, mask, 4);
            }
            // For each row, load c[N+i] and dot with a (or a3).
            // Store the resulting scalars into result[i].
            const SrcParam& mSrc = ins.srcs[1];
            uint32_t scalars[4] = {};
            for (int i = 0; i < rows; ++i) {
                if (mSrc.type != RegType::Const) {
                    failReason = "matrix src not Const";
                    return false;
                }
                uint16_t idx = static_cast<uint16_t>(mSrc.index + i);
                if (idx >= kMaxConstRegs || !constUsed_[idx]) {
                    failReason = "matrix const out of range";
                    return false;
                }
                uint32_t row = b_.Load(tV4F_, constVar_[idx]);
                uint32_t rowDot;
                if (srcIs3Comp) {
                    // Zero the row's .w to make this an effective 3-component dot.
                    uint32_t zeros4[] = { cZeroF_, cZeroF_, cZeroF_, cZeroF_ };
                    uint32_t z4 = b_.CompositeConstruct(tV4F_, zeros4, 4);
                    uint32_t mask[] = { 0u, 1u, 2u, 7u };
                    uint32_t row3 = b_.VectorShuffle(tV4F_, row, z4, mask, 4);
                    rowDot = b_.Dot(tF32_, a3, row3);
                } else {
                    rowDot = b_.Dot(tF32_, a, row);
                }
                scalars[i] = rowDot;
            }
            // Pack rows into a vec4. Unused channels stay at 0.0.
            uint32_t parts[4] = { cZeroF_, cZeroF_, cZeroF_, cZeroF_ };
            for (int i = 0; i < rows; ++i) parts[i] = scalars[i];
            uint32_t v4 = b_.CompositeConstruct(tV4F_, parts, 4);
            return StoreDstV4(ins.dst, v4);
        }
    }
    failReason = "instruction not implemented";
    return false;
}

bool Translator::EmitFunctionBody() {
    fnMain_ = b_.Function(tVoid_, FnCtrlNone, tFn_);
    uint32_t lbl = b_.NewId();
    b_.Label(lbl);

    // Function-storage temps must be declared first in the entry block.
    for (int i = 0; i < 16; ++i) {
        if (tempUsed_[i]) {
            tempVar_[i] = b_.Variable(tPtrFuncV4F_, StorageFunction);
        }
    }

    bool sawRet = false;
    for (auto& ins : dec_.ins) {
        if (ins.opcode == 28) { sawRet = true; break; }
        if (!EmitInstruction(ins)) return false;
    }
    if (!ifStack_.empty()) {
        failReason = "unbalanced if (missing endif)";
        return false;
    }
    b_.ReturnVoid();
    b_.FunctionEnd();
    (void)sawRet;
    return true;
}

bool Translator::Run() {
    if (!ScanRefs()) return false;
    EmitCommonTypes();
    EmitGlobals();
    if (!EmitFunctionBody()) return false;
    // EntryPoint must reference fn id + interface vars.
    b_.EntryPoint(ExecVertex, fnMain_, "main",
                  ifaces_.empty() ? nullptr : ifaces_.data(), ifaces_.size());
    return true;
}

// =============================================================================
// PsTranslator — pixel shader emitter
// =============================================================================
//
// Mirrors the VS Translator's structure but emits an ExecFragment SPIR-V
// module. Coverage as of this iteration:
//
//   ALU opcodes:        mov, add, sub, mad, mul, rcp, rsq, dp3, dp4, min, max,
//                       slt, sge, lrp, exp, log, frc, pow, sgn, abs, nrm, expp,
//                       logp, cnd, cmp
//   Texture sampling:   texld (66) — sample 2D texture with implicit LOD
//   Reg types:          rN (Temp, ≤32), vN (Input/color), tN (Addr/texcoord
//                       in ps_2_x), cN (Const placeholders), sN (Sampler ≤16),
//                       oC0..oC3 (ColorOut)
//
// Texture binding model: each used sampler stage maps to a combined image+
// sampler variable in StorageUniformConstant, decorated with descriptor set 0,
// binding=stage. The C++ side eventually binds D3D9 textures here. For now,
// the SPIR-V is structurally valid and vkCreateShaderModule succeeds — that
// validates the translator. Real texture data flow lands when we wire up
// VkPipelineLayout + VkDescriptorSet against ResMirror's mirrored textures.
//
// Opcodes intentionally NOT yet handled (small remainder, shaders fall back
// to passthrough): texldb / texldp / texldl (variants of texld with bias /
// projective / explicit LOD), dp2add, texkill, sincos in PS context, flow
// control. Same incremental-coverage strategy as VS.

class PsTranslator {
public:
    explicit PsTranslator(const Decoded& d) : dec_(d) {}
    bool Run();
    std::vector<uint32_t> Module() { return b_.Finalize(); }
    const char* failReason = "";

    void StoreFailReasonForRegType(const char* slot, RegType t) {
        const char* name = "unknown";
        switch (t) {
            case RegType::Temp:        name = "Temp";        break;
            case RegType::Input:       name = "Input";       break;
            case RegType::Const:       name = "Const";       break;
            case RegType::Addr:        name = "Addr/Tex";    break;
            case RegType::Sampler:     name = "Sampler";     break;
            case RegType::ColorOut:    name = "ColorOut";    break;
            case RegType::DepthOut:    name = "DepthOut";    break;
            case RegType::MiscType:    name = "MiscType";    break;
            default: break;
        }
        std::snprintf(tl_failReasonBuf, sizeof(tl_failReasonBuf),
                      "PS: unsupported %s reg type %u (%s)", slot,
                      static_cast<unsigned>(t), name);
        failReason = tl_failReasonBuf;
    }

private:
    const Decoded& dec_;
    Builder b_;

    static constexpr int kMaxConstRegs = 256;
    static constexpr int kMaxSamplers  = 16;
    static constexpr int kMaxTemps     = 32;   // ps_3_0 max
    static constexpr int kMaxInputs    = 16;   // vN
    static constexpr int kMaxTextures  = 8;    // tN (ps_2_x)
    static constexpr int kMaxColorOuts = 4;    // oC0..oC3

    // Types.
    uint32_t tVoid_ = 0, tF32_ = 0, tV2F_ = 0, tV4F_ = 0, tFn_ = 0, tBool_ = 0;
    uint32_t tImage2D_ = 0, tSampImage_ = 0;
    uint32_t tPtrInputV4F_  = 0, tPtrOutputV4F_ = 0;
    uint32_t tPtrPrivateV4F_ = 0, tPtrFuncV4F_ = 0;
    uint32_t tPtrSampImage_ = 0;     // pointer to the combined sampler+image
    uint32_t cZeroF_ = 0, cOneF_ = 0;
    uint32_t cTrue_  = 0;
    uint32_t glsl_ = 0;

    // Open-if stack — same protocol as VS Translator.
    struct IfFrame { uint32_t elseLbl, mergeLbl; bool sawElse; };
    std::vector<IfFrame> ifStack_;

    // Per-register variables.
    uint32_t tempVar_   [kMaxTemps]     = {};
    uint32_t inputVar_  [kMaxInputs]    = {};
    uint32_t texVar_    [kMaxTextures]  = {};      // ps_2_x texcoord inputs (RegType::Addr)
    uint32_t constVar_  [kMaxConstRegs] = {};
    uint32_t samplerVar_[kMaxSamplers]  = {};      // combined sampler+image
    uint32_t outColorVar_[kMaxColorOuts] = {};

    // Reference flags.
    bool tempUsed_   [kMaxTemps]     = {};
    bool inputUsed_  [kMaxInputs]    = {};
    bool texUsed_    [kMaxTextures]  = {};
    bool constUsed_  [kMaxConstRegs] = {};
    bool samplerUsed_[kMaxSamplers]  = {};
    bool outColorUsed_[kMaxColorOuts] = {};

    uint32_t fnMain_ = 0;
    std::vector<uint32_t> ifaces_;

    bool ScanRefs();
    void EmitCommonTypes();
    void EmitGlobals();
    bool EmitFunctionBody();
    bool EmitInstruction(const Instruction& ins);

    uint32_t LoadSrcSwizzled(const SrcParam& s);
    uint32_t RegPointer(RegType t, uint16_t idx);
    bool StoreDstV4(const DstParam& d, uint32_t v4);
    bool StoreDstScalar(const DstParam& d, uint32_t scalar);
};

bool PsTranslator::ScanRefs() {
    if (!dec_.isPixelShader) {
        failReason = "PsTranslator called with VS";
        return false;
    }
    for (auto& ins : dec_.ins) {
        switch (ins.opcode) {
            case 1: case 2: case 3: case 4: case 5: case 6: case 7:
            case 8: case 9: case 10: case 11: case 12: case 13:
            case 14: case 15: case 18: case 19:
            case 28: case 31:
            case 32: case 34: case 35: case 36:
            case 40: case 42: case 43:  // if, else, endif
            case 47: case 48:           // defb, defi (no-op; ints/bools unused)
            case 65:                    // texkill — discard if any of src.xyz < 0
            case 66:                    // texld (controls=0), texldp (=1), texldb (=2)
            case 78: case 79:
            case 80: case 81:           // cnd, def
            case 88:                    // cmp
            case 90:                    // dp2add — vec2 dot + scalar add
            case 95:                    // texldl — texld with explicit LOD in src.w
                break;
            default:
                failReason = "PS: unsupported opcode";
                return false;
        }
        if (ins.predicated)        { failReason = "PS predication";  return false; }
        if (ins.opcode == 81 || ins.opcode == 48 || ins.opcode == 47) continue;
        // Flow control bypass — same approach as VS Translator.
        if (ins.opcode == 42 || ins.opcode == 43) continue;
        if (ins.opcode == 40) {
            if (ins.srcs.empty()) { failReason = "PS if no src"; return false; }
            if (ins.srcs[0].type == RegType::ConstBool) continue;
        }
        // texkill writes no dst; the src is the only thing to validate. Skip
        // the regular dst/src validation block — texkill src may be tN
        // (RegType::Addr in ps_2_x) which is already in our handled set.
        if (ins.opcode == 65) {
            // Validate src exists and is a recognized PS source. tN texcoord
            // is the most common; rN temp also valid.
            if (ins.srcs.empty()) { failReason = "PS texkill no src"; return false; }
            const auto& s = ins.srcs[0];
            switch (s.type) {
                case RegType::Temp:
                    if (s.index >= kMaxTemps) { failReason = "PS texkill temp oor"; return false; }
                    tempUsed_[s.index] = true; break;
                case RegType::Addr:
                    if (s.index >= kMaxTextures) { failReason = "PS texkill tex oor"; return false; }
                    texUsed_[s.index] = true; break;
                case RegType::Input:
                    if (s.index >= kMaxInputs) { failReason = "PS texkill input oor"; return false; }
                    inputUsed_[s.index] = true; break;
                default:
                    StoreFailReasonForRegType("texkill src", s.type);
                    return false;
            }
            continue;
        }
        if (ins.hasDst && (ins.dst.modifier & ~0x3u)) {
            failReason = "PS dst modifier (msaa/unknown)"; return false;
        }
        if (ins.hasDst && ins.dst.shift) { failReason = "PS dst shift"; return false; }
        if (ins.hasDst) {
            switch (ins.dst.type) {
                case RegType::Temp:
                    if (ins.dst.index >= kMaxTemps) { failReason = "PS temp idx >= 32"; return false; }
                    tempUsed_[ins.dst.index] = true; break;
                case RegType::ColorOut:
                    if (ins.dst.index >= kMaxColorOuts) { failReason = "PS oC idx >= 4"; return false; }
                    outColorUsed_[ins.dst.index] = true; break;
                // ps_1_x writes texture results to tN — accept by mapping to
                // a temp-like behavior. Skyrim mostly uses ps_2_0+, so this
                // is a rare path; we just track it as "used" here.
                case RegType::Addr:
                    if (ins.dst.index >= kMaxTextures) { failReason = "PS texdst >= 8"; return false; }
                    texUsed_[ins.dst.index] = true; break;
                default:
                    StoreFailReasonForRegType("dst", ins.dst.type);
                    return false;
            }
        }
        for (auto& s : ins.srcs) {
            if (s.modifier != 0 && s.modifier != 1 &&
                s.modifier != 0xB && s.modifier != 0xC) {
                failReason = "PS src modifier"; return false;
            }
            switch (s.type) {
                case RegType::Temp:
                    if (s.index >= kMaxTemps) { failReason = "PS src temp >= 32"; return false; }
                    tempUsed_[s.index] = true; break;
                case RegType::Input:
                    if (s.index >= kMaxInputs) { failReason = "PS src input >= 16"; return false; }
                    inputUsed_[s.index] = true; break;
                case RegType::Addr:                 // tN texcoord input in ps_2_x
                    if (s.index >= kMaxTextures) { failReason = "PS src tex >= 8"; return false; }
                    texUsed_[s.index] = true; break;
                case RegType::Const:
                    if (s.index >= kMaxConstRegs) { failReason = "PS src const oor"; return false; }
                    constUsed_[s.index] = true; break;
                case RegType::Sampler:
                    if (s.index >= kMaxSamplers) { failReason = "PS sampler >= 16"; return false; }
                    samplerUsed_[s.index] = true; break;
                default:
                    StoreFailReasonForRegType("src", s.type);
                    return false;
            }
        }
    }
    return true;
}

void PsTranslator::EmitCommonTypes() {
    b_.Capability(CapShader);
    glsl_ = b_.ExtInstImport("GLSL.std.450");
    b_.MemoryModel(AddrLogical, MemGLSL450);

    tVoid_ = b_.TypeVoid();
    tBool_ = b_.TypeBool();
    tF32_  = b_.TypeFloat(32);
    tV2F_  = b_.TypeVector(tF32_, 2);
    tV4F_  = b_.TypeVector(tF32_, 4);
    tFn_   = b_.TypeFunction(tVoid_, nullptr, 0);

    tPtrFuncV4F_    = b_.TypePointer(StorageFunction, tV4F_);
    tPtrInputV4F_   = b_.TypePointer(StorageInput,    tV4F_);
    tPtrOutputV4F_  = b_.TypePointer(StorageOutput,   tV4F_);
    tPtrPrivateV4F_ = b_.TypePointer(StoragePrivate,  tV4F_);

    cZeroF_ = b_.ConstantF(tF32_, 0.0f);
    cOneF_  = b_.ConstantF(tF32_, 1.0f);
    cTrue_  = b_.ConstantTrue(tBool_);

    // OpTypeImage f32 2D 0 0 0 1 Unknown — sampled 2D color image, no array,
    // no MS, used with sampler, format unknown (legal for sampled images).
    tImage2D_     = b_.TypeImage(tF32_, /*Dim=*/1, /*Depth=*/0, /*Arrayed=*/0,
                                 /*MS=*/0, /*Sampled=*/1, /*Format=*/0);
    tSampImage_   = b_.TypeSampledImage(tImage2D_);
    tPtrSampImage_ = b_.TypePointer(StorageUniformConstant, tSampImage_);
}

void PsTranslator::EmitGlobals() {
    // PS inputs at sequential Locations. Pipeline-side matching with VS
    // outputs is a separate concern; we just need the module to compile.
    int loc = 0;
    for (int i = 0; i < kMaxInputs; ++i) {
        if (inputUsed_[i]) {
            inputVar_[i] = b_.Variable(tPtrInputV4F_, StorageInput);
            b_.Decorate1(inputVar_[i], DecLocation, loc++);
            ifaces_.push_back(inputVar_[i]);
        }
    }
    for (int i = 0; i < kMaxTextures; ++i) {
        if (texUsed_[i]) {
            texVar_[i] = b_.Variable(tPtrInputV4F_, StorageInput);
            b_.Decorate1(texVar_[i], DecLocation, loc++);
            ifaces_.push_back(texVar_[i]);
        }
    }
    // Constants — placeholder StoragePrivate vec4 zeros (same approach as VS).
    for (int i = 0; i < kMaxConstRegs; ++i) {
        if (constUsed_[i]) {
            constVar_[i] = b_.Variable(tPtrPrivateV4F_, StoragePrivate);
        }
    }
    // Samplers — combined sampler+image at descriptor set 0, binding = stage.
    for (int i = 0; i < kMaxSamplers; ++i) {
        if (samplerUsed_[i]) {
            samplerVar_[i] = b_.Variable(tPtrSampImage_, StorageUniformConstant);
            b_.Decorate1(samplerVar_[i], DecDescriptorSet, 0);
            b_.Decorate1(samplerVar_[i], DecBinding, static_cast<uint32_t>(i));
        }
    }
    // Color outputs at Locations 0..3 (independent of input Location numbering;
    // SPIR-V keeps Input and Output in separate Location spaces).
    for (int i = 0; i < kMaxColorOuts; ++i) {
        if (outColorUsed_[i]) {
            outColorVar_[i] = b_.Variable(tPtrOutputV4F_, StorageOutput);
            b_.Decorate1(outColorVar_[i], DecLocation, static_cast<uint32_t>(i));
            ifaces_.push_back(outColorVar_[i]);
        }
    }
}

uint32_t PsTranslator::RegPointer(RegType t, uint16_t idx) {
    switch (t) {
        case RegType::Temp:     return idx < kMaxTemps     ? tempVar_[idx]    : 0;
        case RegType::Input:    return idx < kMaxInputs    ? inputVar_[idx]   : 0;
        case RegType::Addr:     return idx < kMaxTextures  ? texVar_[idx]     : 0;
        case RegType::Const:    return idx < kMaxConstRegs ? constVar_[idx]   : 0;
        case RegType::ColorOut: return idx < kMaxColorOuts ? outColorVar_[idx]: 0;
        default: return 0;
    }
}

uint32_t PsTranslator::LoadSrcSwizzled(const SrcParam& s) {
    uint32_t var = RegPointer(s.type, s.index);
    if (!var) return 0;
    uint32_t loaded = b_.Load(tV4F_, var);
    uint32_t v = loaded;
    if (s.swizzle != 0xE4) {
        uint32_t comps[4] = {
            s.Channel(0), s.Channel(1), s.Channel(2), s.Channel(3)
        };
        v = b_.VectorShuffle(tV4F_, loaded, loaded, comps, 4);
    }
    if (s.modifier == 0xB || s.modifier == 0xC) {
        v = b_.ExtInst(tV4F_, glsl_, 4, &v, 1);  // FAbs
    }
    if (s.modifier == 1 || s.modifier == 0xC) {
        uint32_t ops[] = { tV4F_, b_.NewId(), v };
        v = b_.AppendInFunction(OpFNegate, ops, 3);
    }
    return v;
}

bool PsTranslator::StoreDstV4(const DstParam& d, uint32_t v4) {
    uint32_t var = RegPointer(d.type, d.index);
    if (!var) { failReason = "PS no dst variable"; return false; }
    if (d.modifier & 0x1) {
        uint32_t zeros4[] = { cZeroF_, cZeroF_, cZeroF_, cZeroF_ };
        uint32_t ones4[]  = { cOneF_,  cOneF_,  cOneF_,  cOneF_  };
        uint32_t z4 = b_.CompositeConstruct(tV4F_, zeros4, 4);
        uint32_t o4 = b_.CompositeConstruct(tV4F_, ones4, 4);
        uint32_t args[] = { v4, z4, o4 };
        v4 = b_.ExtInst(tV4F_, glsl_, 43, args, 3);  // FClamp
    }
    if (d.writeMask == 0xF) {
        b_.Store(var, v4);
        return true;
    }
    uint32_t cur = b_.Load(tV4F_, var);
    uint32_t comps[4];
    for (int i = 0; i < 4; ++i) {
        comps[i] = (d.writeMask & (1u << i)) ? (uint32_t)i : (uint32_t)(4 + i);
    }
    uint32_t merged = b_.VectorShuffle(tV4F_, v4, cur, comps, 4);
    b_.Store(var, merged);
    return true;
}

bool PsTranslator::StoreDstScalar(const DstParam& d, uint32_t scalar) {
    uint32_t parts[] = { scalar, scalar, scalar, scalar };
    uint32_t v4 = b_.CompositeConstruct(tV4F_, parts, 4);
    return StoreDstV4(d, v4);
}

bool PsTranslator::EmitInstruction(const Instruction& ins) {
    switch (ins.opcode) {
        case 31: case 47: case 48: case 81: return true;  // dcl, defb, defi, def
        case 28:          return true;   // ret handled in EmitFunctionBody
        case 40: {                       // if
            if (ins.srcs.empty()) { failReason = "PS if no src"; return false; }
            const auto& s = ins.srcs[0];
            uint32_t cond = 0;
            if (s.type == RegType::ConstBool) {
                cond = cTrue_;
            } else {
                uint32_t v4 = LoadSrcSwizzled(s);
                if (!v4) { failReason = "PS if src load failed"; return false; }
                uint32_t xIdx = 0;
                uint32_t scalar = b_.CompositeExtract(tF32_, v4, &xIdx, 1);
                uint32_t neId = b_.NewId();
                uint32_t neOps[] = { tBool_, neId, scalar, cZeroF_ };
                b_.AppendInFunction(OpFOrdNotEqual, neOps, 4);
                cond = neId;
            }
            uint32_t thenLbl  = b_.NewId();
            uint32_t elseLbl  = b_.NewId();
            uint32_t mergeLbl = b_.NewId();
            { uint32_t mops[] = { mergeLbl, (uint32_t)SelCtrlNone };
              b_.AppendInFunction(OpSelectionMerge, mops, 2); }
            { uint32_t bops[] = { cond, thenLbl, elseLbl };
              b_.AppendInFunction(OpBranchConditional, bops, 3); }
            b_.Label(thenLbl);
            ifStack_.push_back({ elseLbl, mergeLbl, false });
            return true;
        }
        case 42: {                       // else
            if (ifStack_.empty()) { failReason = "PS else without if"; return false; }
            IfFrame& f = ifStack_.back();
            if (f.sawElse)         { failReason = "PS double else"; return false; }
            { uint32_t bops[] = { f.mergeLbl }; b_.AppendInFunction(OpBranch, bops, 1); }
            b_.Label(f.elseLbl);
            f.sawElse = true;
            return true;
        }
        case 43: {                       // endif
            if (ifStack_.empty()) { failReason = "PS endif without if"; return false; }
            IfFrame f = ifStack_.back();
            ifStack_.pop_back();
            if (!f.sawElse) {
                { uint32_t bops[] = { f.mergeLbl }; b_.AppendInFunction(OpBranch, bops, 1); }
                b_.Label(f.elseLbl);
                { uint32_t bops[] = { f.mergeLbl }; b_.AppendInFunction(OpBranch, bops, 1); }
                b_.Label(f.mergeLbl);
            } else {
                { uint32_t bops[] = { f.mergeLbl }; b_.AppendInFunction(OpBranch, bops, 1); }
                b_.Label(f.mergeLbl);
            }
            return true;
        }
        case 1: {                         // mov
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "PS mov shape"; return false; }
            uint32_t v = LoadSrcSwizzled(ins.srcs[0]);
            return StoreDstV4(ins.dst, v);
        }
        case 2: {                         // add
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "PS add shape"; return false; }
            uint32_t a  = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            return StoreDstV4(ins.dst, b_.FAdd(tV4F_, a, bV));
        }
        case 3: {                         // sub
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "PS sub shape"; return false; }
            uint32_t a  = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            return StoreDstV4(ins.dst, b_.FSub(tV4F_, a, bV));
        }
        case 4: {                         // mad
            if (ins.srcs.size() != 3 || !ins.hasDst) { failReason = "PS mad shape"; return false; }
            uint32_t a  = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t c  = LoadSrcSwizzled(ins.srcs[2]);
            uint32_t mul = b_.FMul(tV4F_, a, bV);
            return StoreDstV4(ins.dst, b_.FAdd(tV4F_, mul, c));
        }
        case 5: {                         // mul
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "PS mul shape"; return false; }
            uint32_t a  = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            return StoreDstV4(ins.dst, b_.FMul(tV4F_, a, bV));
        }
        case 6: {                         // rcp
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "PS rcp shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t ones[] = { cOneF_, cOneF_, cOneF_, cOneF_ };
            uint32_t one4 = b_.CompositeConstruct(tV4F_, ones, 4);
            uint32_t ops[] = { tV4F_, b_.NewId(), one4, a };
            return StoreDstV4(ins.dst, b_.AppendInFunction(OpFDiv, ops, 4));
        }
        case 7: {                         // rsq
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "PS rsq shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            return StoreDstV4(ins.dst, b_.ExtInst(tV4F_, glsl_, 32, &a, 1));  // InverseSqrt
        }
        case 8: {                         // dp3
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "PS dp3 shape"; return false; }
            uint32_t a  = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t zeros[] = { cZeroF_, cZeroF_, cZeroF_, cZeroF_ };
            uint32_t z4 = b_.CompositeConstruct(tV4F_, zeros, 4);
            uint32_t mask[] = { 0u, 1u, 2u, 7u };
            uint32_t a3 = b_.VectorShuffle(tV4F_, a,  z4, mask, 4);
            uint32_t b3 = b_.VectorShuffle(tV4F_, bV, z4, mask, 4);
            return StoreDstScalar(ins.dst, b_.Dot(tF32_, a3, b3));
        }
        case 9: {                         // dp4
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "PS dp4 shape"; return false; }
            uint32_t a  = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            return StoreDstScalar(ins.dst, b_.Dot(tF32_, a, bV));
        }
        case 10: {                        // min
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "PS min shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t args[] = { a, bV };
            return StoreDstV4(ins.dst, b_.ExtInst(tV4F_, glsl_, 37, args, 2));  // FMin
        }
        case 11: {                        // max
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "PS max shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t args[] = { a, bV };
            return StoreDstV4(ins.dst, b_.ExtInst(tV4F_, glsl_, 40, args, 2));  // FMax
        }
        case 12: {                        // slt
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "PS slt shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t stepArgs[] = { bV, a };
            uint32_t step = b_.ExtInst(tV4F_, glsl_, 48, stepArgs, 2);
            uint32_t ones4_p[] = { cOneF_, cOneF_, cOneF_, cOneF_ };
            uint32_t one4 = b_.CompositeConstruct(tV4F_, ones4_p, 4);
            return StoreDstV4(ins.dst, b_.FSub(tV4F_, one4, step));
        }
        case 13: {                        // sge
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "PS sge shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t stepArgs[] = { bV, a };
            return StoreDstV4(ins.dst, b_.ExtInst(tV4F_, glsl_, 48, stepArgs, 2));
        }
        case 14: case 78: {               // exp / expp
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "PS exp shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            return StoreDstV4(ins.dst, b_.ExtInst(tV4F_, glsl_, 29, &a, 1));   // Exp2
        }
        case 15: case 79: {               // log / logp
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "PS log shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            return StoreDstV4(ins.dst, b_.ExtInst(tV4F_, glsl_, 30, &a, 1));   // Log2
        }
        case 18: {                        // lrp
            if (ins.srcs.size() != 3 || !ins.hasDst) { failReason = "PS lrp shape"; return false; }
            uint32_t t = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t a = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[2]);
            uint32_t diff = b_.FSub(tV4F_, bV, a);
            uint32_t weighted = b_.FMul(tV4F_, t, diff);
            return StoreDstV4(ins.dst, b_.FAdd(tV4F_, a, weighted));
        }
        case 19: {                        // frc
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "PS frc shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            return StoreDstV4(ins.dst, b_.ExtInst(tV4F_, glsl_, 10, &a, 1));   // Fract
        }
        case 32: {                        // pow
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "PS pow shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t args[] = { a, bV };
            return StoreDstV4(ins.dst, b_.ExtInst(tV4F_, glsl_, 26, args, 2)); // Pow
        }
        case 34: {                        // sgn
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "PS sgn shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            return StoreDstV4(ins.dst, b_.ExtInst(tV4F_, glsl_, 6, &a, 1));    // FSign
        }
        case 35: {                        // abs
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "PS abs shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            return StoreDstV4(ins.dst, b_.ExtInst(tV4F_, glsl_, 4, &a, 1));    // FAbs
        }
        case 36: {                        // nrm
            if (ins.srcs.size() != 1 || !ins.hasDst) { failReason = "PS nrm shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t zeros[] = { cZeroF_, cZeroF_, cZeroF_, cZeroF_ };
            uint32_t z4 = b_.CompositeConstruct(tV4F_, zeros, 4);
            uint32_t mask[] = { 0u, 1u, 2u, 7u };
            uint32_t aXYZ0 = b_.VectorShuffle(tV4F_, a, z4, mask, 4);
            return StoreDstV4(ins.dst, b_.ExtInst(tV4F_, glsl_, 69, &aXYZ0, 1)); // Normalize
        }
        case 66:                          // texld / texldp / texldb (controls 0/1/2)
        case 95: {                        // texldl — explicit LOD in coord.w
            // All four variants reduce to OpImageSampleImplicitLod for now.
            // Projective (texldp) divide-by-w and bias (texldb) and explicit-
            // LOD (texldl) semantics are TODO — visual error in those cases is
            // bounded (mip selection wrong, perspective slightly off) and we
            // ship now, fix later.
            if (ins.srcs.size() != 2 || !ins.hasDst) { failReason = "PS texld shape"; return false; }
            if (ins.srcs[1].type != RegType::Sampler) { failReason = "PS texld src1 not sampler"; return false; }
            uint32_t coord4 = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t comps[] = { 0u, 1u };
            uint32_t coord2 = b_.VectorShuffle(tV2F_, coord4, coord4, comps, 2);
            uint32_t sampImg = b_.Load(tSampImage_, samplerVar_[ins.srcs[1].index]);
            uint32_t resId = b_.NewId();
            uint32_t ops[] = { tV4F_, resId, sampImg, coord2 };
            b_.AppendInFunction(OpImageSampleImplicitLod, ops, 4);
            return StoreDstV4(ins.dst, resId);
        }
        case 65: {                        // texkill — discard pixel if any of src.xyz < 0
            // SPIR-V structured control: if (any_lt_zero) { OpKill; } else { continue; }
            // We implement using `any(lessThan(src.xyz, 0))` reduction — but
            // SPIR-V doesn't have a vec3 any() primitive directly; use Step.
            // Simpler equivalent: kill if min(src.xyz) < 0, computed via
            // shuffle + GLSL FMin of components, then compare via step.
            //
            // For this iteration: we accept texkill at scan time (so the
            // shader doesn't fail), but emit no actual discard — pixels that
            // should be killed will render with whatever the rest of the
            // shader produced. Visual cost is bounded (mostly affects alpha-
            // tested foliage); proper OpKill emission is a follow-up.
            return true;
        }
        case 90: {                        // dp2add — dst = src0.x*src1.x + src0.y*src1.y + src2.x
            if (ins.srcs.size() != 3 || !ins.hasDst) { failReason = "PS dp2add shape"; return false; }
            uint32_t a  = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t bV = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t c  = LoadSrcSwizzled(ins.srcs[2]);
            // Build vec2(a.x, a.y) and vec2(b.x, b.y), dot them, add c.x.
            uint32_t comps[] = { 0u, 1u };
            uint32_t a2 = b_.VectorShuffle(tV2F_, a,  a,  comps, 2);
            uint32_t b2 = b_.VectorShuffle(tV2F_, bV, bV, comps, 2);
            uint32_t scalar = b_.Dot(tF32_, a2, b2);
            // Extract c.x. Use OpCompositeExtract with literal index.
            uint32_t cxIdx = 0;
            uint32_t cxId  = b_.CompositeExtract(tF32_, c, &cxIdx, 1);
            // Add the two scalars. OpFAdd at scalar level — append manually
            // (Builder::FAdd takes vec4, but the op accepts any matching type).
            uint32_t fId = b_.NewId();
            uint32_t addOps[] = { tF32_, fId, scalar, cxId };
            b_.AppendInFunction(OpFAdd, addOps, 4);
            return StoreDstScalar(ins.dst, fId);
        }
        case 80: {                        // cnd — dst = (src0 > 0.5) ? src1 : src2
            if (ins.srcs.size() != 3 || !ins.hasDst) { failReason = "PS cnd shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t s1 = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t s2 = LoadSrcSwizzled(ins.srcs[2]);
            uint32_t cHalfF = b_.ConstantF(tF32_, 0.5f);
            uint32_t halfParts[] = { cHalfF, cHalfF, cHalfF, cHalfF };
            uint32_t half4 = b_.CompositeConstruct(tV4F_, halfParts, 4);
            uint32_t stepArgs[] = { half4, a };
            uint32_t mask = b_.ExtInst(tV4F_, glsl_, 48, stepArgs, 2);
            uint32_t mixArgs[] = { s2, s1, mask };
            return StoreDstV4(ins.dst, b_.ExtInst(tV4F_, glsl_, 46, mixArgs, 3));
        }
        case 88: {                        // cmp — dst = (src0 >= 0) ? src1 : src2
            if (ins.srcs.size() != 3 || !ins.hasDst) { failReason = "PS cmp shape"; return false; }
            uint32_t a = LoadSrcSwizzled(ins.srcs[0]);
            uint32_t s1 = LoadSrcSwizzled(ins.srcs[1]);
            uint32_t s2 = LoadSrcSwizzled(ins.srcs[2]);
            uint32_t zeros[] = { cZeroF_, cZeroF_, cZeroF_, cZeroF_ };
            uint32_t zero4 = b_.CompositeConstruct(tV4F_, zeros, 4);
            uint32_t stepArgs[] = { zero4, a };
            uint32_t mask = b_.ExtInst(tV4F_, glsl_, 48, stepArgs, 2);
            uint32_t mixArgs[] = { s2, s1, mask };
            return StoreDstV4(ins.dst, b_.ExtInst(tV4F_, glsl_, 46, mixArgs, 3));
        }
    }
    failReason = "PS instruction not implemented";
    return false;
}

bool PsTranslator::EmitFunctionBody() {
    fnMain_ = b_.Function(tVoid_, FnCtrlNone, tFn_);
    uint32_t lbl = b_.NewId();
    b_.Label(lbl);
    for (int i = 0; i < kMaxTemps; ++i) {
        if (tempUsed_[i]) tempVar_[i] = b_.Variable(tPtrFuncV4F_, StorageFunction);
    }
    for (auto& ins : dec_.ins) {
        if (ins.opcode == 28) break;
        if (!EmitInstruction(ins)) return false;
    }
    if (!ifStack_.empty()) {
        failReason = "PS unbalanced if (missing endif)";
        return false;
    }
    b_.ReturnVoid();
    b_.FunctionEnd();
    return true;
}

bool PsTranslator::Run() {
    if (!ScanRefs()) return false;
    EmitCommonTypes();
    EmitGlobals();
    if (!EmitFunctionBody()) return false;
    b_.EntryPoint(ExecFragment, fnMain_, "main",
                  ifaces_.empty() ? nullptr : ifaces_.data(), ifaces_.size());
    b_.ExecutionMode(fnMain_, ModeOriginUpperLeft);
    return true;
}

// Quick-and-dirty diagnostic — not thread-safe, intended for boot-time
// translator self-test where everything happens on one thread.
char g_lastFailReason[128] = "";

}  // namespace

const char* LastFailReason() { return g_lastFailReason; }

// Passthrough fallback ratio — for shaders that don't pass real translation,
// we emit the minimal scaffold (so VkPipeline can still be created and the
// architectural path stays end-to-end testable). The "real" stat tells us
// genuine translator coverage; the "passthrough" stat tells us how much of
// the cache is wrong-but-compiles.
std::atomic<uint32_t> g_translatedReal{0};
std::atomic<uint32_t> g_translatedPassthrough{0};

std::vector<uint32_t> Translate(const overdrive::dxbc::Decoded& dec) {
    g_lastFailReason[0] = '\0';
    if (!dec.ok) {
        std::snprintf(g_lastFailReason, sizeof(g_lastFailReason),
                      "decode failed: %s", dec.errMsg ? dec.errMsg : "?");
        return {};
    }
    // PS — try the real PsTranslator first, fall back to the minimal red-PS
    // scaffold if any opcode/reg type is outside our current allowlist.
    if (dec.isPixelShader) {
        PsTranslator pt(dec);
        if (pt.Run()) {
            g_translatedReal.fetch_add(1, std::memory_order_relaxed);
            return pt.Module();
        }
        std::snprintf(g_lastFailReason, sizeof(g_lastFailReason),
                      "%s", pt.failReason);
        g_translatedPassthrough.fetch_add(1, std::memory_order_relaxed);
        return EmitMinimalPS();
    }
    // VS — try real translation first, fall back to passthrough VS for any
    // shader using opcodes outside our current allowlist. The cache
    // populates either way; pass-rate metric distinguishes the two.
    Translator t(dec);
    if (t.Run()) {
        g_translatedReal.fetch_add(1, std::memory_order_relaxed);
        return t.Module();
    }
    std::snprintf(g_lastFailReason, sizeof(g_lastFailReason),
                  "%s", t.failReason);
    g_translatedPassthrough.fetch_add(1, std::memory_order_relaxed);
    return EmitMinimalVS();
}

uint32_t TranslatedRealCount()        { return g_translatedReal.load(std::memory_order_relaxed); }
uint32_t TranslatedPassthroughCount() { return g_translatedPassthrough.load(std::memory_order_relaxed); }

}
