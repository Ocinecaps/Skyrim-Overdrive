#pragma once
#include <cstdint>
#include <vector>

namespace overdrive::spirv {

// =============================================================================
// SpirvBuilder — minimal SPIR-V binary writer
// =============================================================================
//
// Builds a binary SPIR-V module (std::vector<uint32_t>) suitable for handing
// directly to vkCreateShaderModule. Works at the level of raw opcodes + result
// IDs — no type system, no expression trees.
//
// SPIR-V module layout (from the spec):
//   Header (5 words):
//     0x07230203  magic
//     0x00010000  version 1.0  (Vulkan 1.0+; we target 1.2 which accepts up to 1.5)
//     0x00000000  generator magic (0 = unspecified, fine for our case)
//     <bound>     largest ID + 1
//     0x00000000  reserved
//   Then sections in this exact order (the validator enforces it):
//     1. OpCapability instructions
//     2. OpExtension instructions
//     3. OpExtInstImport instructions
//     4. OpMemoryModel (exactly one)
//     5. OpEntryPoint instructions
//     6. OpExecutionMode instructions
//     7. Debug instructions (OpSource, OpName, OpMemberName, OpString)
//     8. Annotation instructions (OpDecorate, OpMemberDecorate, OpGroupDecorate)
//     9. Type, constant, and global variable declarations
//    10. Function definitions
//
// We keep one DWORD vector per section and concatenate at Finalize() — that way
// callers can add instructions in any order while we still produce a spec-
// compliant module.
//
// Instruction encoding: word 0 = (opcode & 0xFFFF) | (wordCount << 16).
// `wordCount` includes word 0 itself.

// SPIR-V opcode subset we use. Names match the spec verbatim. The values are
// fixed by the SPIR-V Khronos registry — never to be edited.
enum Op : uint16_t {
    OpNop                 = 0,
    OpUndef               = 1,
    OpSourceContinued     = 2,
    OpSource              = 3,
    OpSourceExtension     = 4,
    OpName                = 5,
    OpMemberName          = 6,
    OpString              = 7,
    OpLine                = 8,
    OpExtension           = 10,
    OpExtInstImport       = 11,
    OpExtInst             = 12,
    OpMemoryModel         = 14,
    OpEntryPoint          = 15,
    OpExecutionMode       = 16,
    OpCapability          = 17,
    OpTypeVoid            = 19,
    OpTypeBool            = 20,
    OpTypeInt             = 21,
    OpTypeFloat           = 22,
    OpTypeVector          = 23,
    OpTypeMatrix          = 24,
    OpTypeImage           = 25,
    OpTypeSampler         = 26,
    OpTypeSampledImage    = 27,
    OpTypeArray           = 28,
    OpTypeRuntimeArray    = 29,
    OpTypeStruct          = 30,
    OpTypePointer         = 32,
    OpTypeFunction        = 33,
    OpConstantTrue        = 41,
    OpConstantFalse       = 42,
    OpConstant            = 43,
    OpConstantComposite   = 44,
    OpFunction            = 54,
    OpFunctionParameter   = 55,
    OpFunctionEnd         = 56,
    OpFunctionCall        = 57,
    OpVariable            = 59,
    OpLoad                = 61,
    OpStore               = 62,
    OpAccessChain         = 65,
    OpDecorate            = 71,
    OpMemberDecorate      = 72,
    OpVectorShuffle       = 79,
    OpCompositeConstruct  = 80,
    OpCompositeExtract    = 81,
    OpCompositeInsert     = 82,
    OpSampledImage        = 86,
    OpImageSampleImplicitLod = 87,
    OpImageSampleExplicitLod = 88,
    OpFNegate             = 127,
    OpFAdd                = 129,
    OpFSub                = 131,
    OpFMul                = 133,
    OpFDiv                = 136,
    OpVectorTimesScalar   = 142,
    OpMatrixTimesVector   = 145,
    OpDot                 = 148,
    OpFOrdEqual           = 180,
    OpFOrdNotEqual        = 182,
    OpFOrdLessThan        = 184,
    OpFOrdGreaterThan     = 186,
    OpFOrdLessThanEqual   = 188,
    OpFOrdGreaterThanEqual= 190,
    OpSelectionMerge      = 247,
    OpLabel               = 248,
    OpBranch              = 249,
    OpBranchConditional   = 250,
    OpReturn              = 253,
    OpReturnValue         = 254,
    OpKill                = 252,
};

enum SelectionControl { SelCtrlNone = 0 };

// Standard SPIR-V enums we touch. Same registry source.
enum SourceLang        { LangUnknown = 0 };
enum AddressingModel   { AddrLogical = 0 };
enum MemoryModelEnum   { MemGLSL450 = 1 };
enum ExecutionModel    { ExecVertex = 0, ExecFragment = 4 };
enum ExecutionMode     { ModeOriginUpperLeft = 7 };
enum Capability        { CapShader = 1 };
enum StorageClass {
    StorageUniformConstant = 0,
    StorageInput           = 1,
    StorageUniform         = 2,
    StorageOutput          = 3,
    StorageWorkgroup       = 4,
    StorageCrossWorkgroup  = 5,
    StoragePrivate         = 6,
    StorageFunction        = 7,
    StoragePushConstant    = 9,
};
enum Decoration {
    DecBlock        = 2,
    DecBuiltIn      = 11,
    DecLocation     = 30,
    DecBinding      = 33,
    DecDescriptorSet= 34,
    DecOffset       = 35,
};
enum BuiltIn { BuiltInPosition = 0, BuiltInPointSize = 1 };
enum FunctionControl { FnCtrlNone = 0 };
enum MemoryAccess    { MemAccessNone = 0 };

class Builder {
public:
    Builder();

    // Allocate a fresh result-ID. IDs are 1-based; ID 0 is reserved.
    uint32_t NewId();

    // High-level helpers — append a single SPIR-V instruction to the
    // appropriate section. Each returns the result-ID where one exists.
    void     Capability(uint32_t cap);
    uint32_t ExtInstImport(const char* name);
    void     MemoryModel(uint32_t addressing, uint32_t memory);
    void     EntryPoint(uint32_t exec, uint32_t fn, const char* name,
                        const uint32_t* ifaces, size_t ifaceCount);
    void     ExecutionMode(uint32_t fn, uint32_t mode);
    void     ExecutionMode1(uint32_t fn, uint32_t mode, uint32_t arg);
    void     Decorate(uint32_t target, uint32_t deco);
    void     Decorate1(uint32_t target, uint32_t deco, uint32_t arg);

    uint32_t TypeVoid();
    uint32_t TypeBool();
    uint32_t TypeFloat(uint32_t bits = 32);
    uint32_t TypeVector(uint32_t componentType, uint32_t count);
    uint32_t TypePointer(uint32_t storageClass, uint32_t pointee);
    uint32_t TypeFunction(uint32_t returnT, const uint32_t* params, size_t paramCount);

    // OpTypeImage. See SPIR-V spec for the operand semantics.
    //   sampledType   = result type from TypeFloat(32) (the channel type)
    //   dim           = 0 1D, 1 2D, 2 3D, 3 Cube, ... (we use 1 for 2D)
    //   depth         = 0 not depth, 1 depth, 2 unknown
    //   arrayed       = 0 non-array, 1 array
    //   ms            = 0 single-sample, 1 multi-sample
    //   sampled       = 0 runtime, 1 sampled (used with sampler), 2 storage image
    //   imageFormat   = 0 Unknown (legal for sampled images)
    uint32_t TypeImage(uint32_t sampledType, uint32_t dim, uint32_t depth,
                       uint32_t arrayed, uint32_t ms, uint32_t sampled,
                       uint32_t imageFormat);
    // OpTypeSampledImage — combines an image type with a sampler. This is what
    // a `uniform sampler2D` in GLSL becomes in SPIR-V (a single combined
    // sampler+image variable in StorageUniformConstant). Using combined samplers
    // simplifies the binding model: one descriptor per texture stage.
    uint32_t TypeSampledImage(uint32_t imageType);

    uint32_t Constant(uint32_t resultType, uint32_t value);     // 32-bit literal
    uint32_t ConstantF(uint32_t resultType, float v);
    uint32_t ConstantComposite(uint32_t resultType, const uint32_t* parts, size_t partCount);
    uint32_t ConstantTrue(uint32_t boolType);
    uint32_t ConstantFalse(uint32_t boolType);

    uint32_t Variable(uint32_t typePtr, uint32_t storageClass);

    // Function-body helpers — append into the current function section.
    uint32_t Function(uint32_t resultType, uint32_t ctrl, uint32_t typeFunction);
    void     Label(uint32_t labelId);
    uint32_t Load(uint32_t resultType, uint32_t pointer);
    void     Store(uint32_t pointer, uint32_t object);
    void     ReturnVoid();
    void     FunctionEnd();

    // Inside-function ALU + composite helpers. All append into the current
    // function section. Returns the result-ID where one is produced.
    uint32_t FAdd(uint32_t resultType, uint32_t a, uint32_t b);
    uint32_t FSub(uint32_t resultType, uint32_t a, uint32_t b);
    uint32_t FMul(uint32_t resultType, uint32_t a, uint32_t b);
    uint32_t Dot (uint32_t resultType, uint32_t a, uint32_t b);
    // Build a composite (vector or struct) from individual component IDs.
    uint32_t CompositeConstruct(uint32_t resultType,
                                const uint32_t* parts, size_t partCount);
    // Extract a single component / member via an integer index path.
    uint32_t CompositeExtract  (uint32_t resultType, uint32_t composite,
                                const uint32_t* indices, size_t indexCount);
    // Cross-vector shuffle: each component in `components` selects from the
    // concatenation of vector1 and vector2.
    uint32_t VectorShuffle(uint32_t resultType,
                           uint32_t v1, uint32_t v2,
                           const uint32_t* components, size_t componentCount);
    // Path-based pointer construction: indices must be ID operands (typically
    // OpConstant ints), not literal integers.
    uint32_t AccessChain(uint32_t resultPtrType, uint32_t base,
                         const uint32_t* indices, size_t indexCount);

    // Generic raw-instruction emitter for the function section. Use this for
    // opcodes that don't have a dedicated helper above (rare). Returns the
    // (caller-allocated) result-ID, which must be operand[1] in `operands`.
    uint32_t AppendInFunction(uint16_t op,
                              const uint32_t* operands, size_t operandCount);

    // OpExtInst — call into an extended instruction set (e.g. GLSL.std.450
    // for FMin/FMax/FAbs/Normalize/InverseSqrt/Fract/...). `set` is the
    // result-ID returned by ExtInstImport. `instruction` is the GLSL.std.450
    // instruction number (e.g. 4 = FAbs, 37 = FMin, 40 = FMax, 69 = Normalize).
    uint32_t ExtInst(uint32_t resultType, uint32_t set, uint32_t instruction,
                     const uint32_t* args, size_t argCount);

    // Concatenate header + sections into a final binary SPIR-V module.
    std::vector<uint32_t> Finalize() const;

private:
    // One section per ordering bucket. Instructions inside each are kept in
    // append order; final module concatenates buckets in spec order.
    std::vector<uint32_t> capabilities_;
    std::vector<uint32_t> extensions_;
    std::vector<uint32_t> extInstImports_;
    std::vector<uint32_t> memoryModel_;
    std::vector<uint32_t> entryPoints_;
    std::vector<uint32_t> execModes_;
    std::vector<uint32_t> debug_;
    std::vector<uint32_t> annotations_;
    std::vector<uint32_t> typesConsts_;   // types, constants, globals
    std::vector<uint32_t> functions_;     // all function bodies
    uint32_t              nextId_ = 1;

    // Append a freshly-encoded SPIR-V instruction into `section`.
    static void AppendOp(std::vector<uint32_t>& section,
                         uint16_t op,
                         const uint32_t* operands, size_t operandCount);

    // Pack a NUL-terminated string into uint32_t words (little-endian, padded
    // with zeros). Returns word count consumed. Spec requires NUL terminator.
    static size_t PackString(const char* s, std::vector<uint32_t>& dst);
};

}
