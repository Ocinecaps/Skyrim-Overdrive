#include "SpirvBuilder.h"

#include <cstring>

namespace overdrive::spirv {

Builder::Builder() = default;

uint32_t Builder::NewId() { return nextId_++; }

void Builder::AppendOp(std::vector<uint32_t>& section,
                       uint16_t op,
                       const uint32_t* operands, size_t operandCount) {
    uint32_t wordCount = static_cast<uint32_t>(1 + operandCount);   // includes word 0
    uint32_t header    = (wordCount << 16) | op;
    section.push_back(header);
    for (size_t i = 0; i < operandCount; ++i) section.push_back(operands[i]);
}

size_t Builder::PackString(const char* s, std::vector<uint32_t>& dst) {
    size_t len = std::strlen(s);
    size_t totalBytes = len + 1;                    // include the NUL
    size_t words = (totalBytes + 3) / 4;            // round up to whole words
    size_t startIdx = dst.size();
    dst.resize(startIdx + words, 0);
    std::memcpy(reinterpret_cast<uint8_t*>(dst.data() + startIdx), s, len);
    // Trailing bytes (incl. the NUL) are already 0 from resize-zero-fill.
    return words;
}

void Builder::Capability(uint32_t cap) {
    AppendOp(capabilities_, OpCapability, &cap, 1);
}

uint32_t Builder::ExtInstImport(const char* name) {
    uint32_t id = NewId();
    std::vector<uint32_t> ops;
    ops.push_back(id);
    PackString(name, ops);
    AppendOp(extInstImports_, OpExtInstImport, ops.data(), ops.size());
    return id;
}

void Builder::MemoryModel(uint32_t addressing, uint32_t memory) {
    uint32_t ops[] = { addressing, memory };
    AppendOp(memoryModel_, OpMemoryModel, ops, 2);
}

void Builder::EntryPoint(uint32_t exec, uint32_t fn, const char* name,
                         const uint32_t* ifaces, size_t ifaceCount) {
    std::vector<uint32_t> ops;
    ops.push_back(exec);
    ops.push_back(fn);
    PackString(name, ops);
    for (size_t i = 0; i < ifaceCount; ++i) ops.push_back(ifaces[i]);
    AppendOp(entryPoints_, OpEntryPoint, ops.data(), ops.size());
}

void Builder::ExecutionMode(uint32_t fn, uint32_t mode) {
    uint32_t ops[] = { fn, mode };
    AppendOp(execModes_, OpExecutionMode, ops, 2);
}

void Builder::ExecutionMode1(uint32_t fn, uint32_t mode, uint32_t arg) {
    uint32_t ops[] = { fn, mode, arg };
    AppendOp(execModes_, OpExecutionMode, ops, 3);
}

void Builder::Decorate(uint32_t target, uint32_t deco) {
    uint32_t ops[] = { target, deco };
    AppendOp(annotations_, OpDecorate, ops, 2);
}

void Builder::Decorate1(uint32_t target, uint32_t deco, uint32_t arg) {
    uint32_t ops[] = { target, deco, arg };
    AppendOp(annotations_, OpDecorate, ops, 3);
}

uint32_t Builder::TypeVoid() {
    uint32_t id = NewId();
    AppendOp(typesConsts_, OpTypeVoid, &id, 1);
    return id;
}

uint32_t Builder::TypeBool() {
    uint32_t id = NewId();
    AppendOp(typesConsts_, OpTypeBool, &id, 1);
    return id;
}

uint32_t Builder::TypeFloat(uint32_t bits) {
    uint32_t id = NewId();
    uint32_t ops[] = { id, bits };
    AppendOp(typesConsts_, OpTypeFloat, ops, 2);
    return id;
}

uint32_t Builder::TypeVector(uint32_t componentType, uint32_t count) {
    uint32_t id = NewId();
    uint32_t ops[] = { id, componentType, count };
    AppendOp(typesConsts_, OpTypeVector, ops, 3);
    return id;
}

uint32_t Builder::TypePointer(uint32_t storageClass, uint32_t pointee) {
    uint32_t id = NewId();
    uint32_t ops[] = { id, storageClass, pointee };
    AppendOp(typesConsts_, OpTypePointer, ops, 3);
    return id;
}

uint32_t Builder::TypeFunction(uint32_t returnT, const uint32_t* params, size_t paramCount) {
    uint32_t id = NewId();
    std::vector<uint32_t> ops;
    ops.push_back(id);
    ops.push_back(returnT);
    for (size_t i = 0; i < paramCount; ++i) ops.push_back(params[i]);
    AppendOp(typesConsts_, OpTypeFunction, ops.data(), ops.size());
    return id;
}

uint32_t Builder::TypeImage(uint32_t sampledType, uint32_t dim, uint32_t depth,
                            uint32_t arrayed, uint32_t ms, uint32_t sampled,
                            uint32_t imageFormat) {
    uint32_t id = NewId();
    uint32_t ops[] = { id, sampledType, dim, depth, arrayed, ms, sampled, imageFormat };
    AppendOp(typesConsts_, OpTypeImage, ops, 8);
    return id;
}

uint32_t Builder::TypeSampledImage(uint32_t imageType) {
    uint32_t id = NewId();
    uint32_t ops[] = { id, imageType };
    AppendOp(typesConsts_, OpTypeSampledImage, ops, 2);
    return id;
}

uint32_t Builder::Constant(uint32_t resultType, uint32_t value) {
    uint32_t id = NewId();
    uint32_t ops[] = { resultType, id, value };
    AppendOp(typesConsts_, OpConstant, ops, 3);
    return id;
}

uint32_t Builder::ConstantF(uint32_t resultType, float v) {
    uint32_t bits;
    std::memcpy(&bits, &v, sizeof(bits));
    return Constant(resultType, bits);
}

uint32_t Builder::ConstantComposite(uint32_t resultType, const uint32_t* parts, size_t partCount) {
    uint32_t id = NewId();
    std::vector<uint32_t> ops;
    ops.push_back(resultType);
    ops.push_back(id);
    for (size_t i = 0; i < partCount; ++i) ops.push_back(parts[i]);
    AppendOp(typesConsts_, OpConstantComposite, ops.data(), ops.size());
    return id;
}

uint32_t Builder::ConstantTrue(uint32_t boolType) {
    uint32_t id = NewId();
    uint32_t ops[] = { boolType, id };
    AppendOp(typesConsts_, OpConstantTrue, ops, 2);
    return id;
}

uint32_t Builder::ConstantFalse(uint32_t boolType) {
    uint32_t id = NewId();
    uint32_t ops[] = { boolType, id };
    AppendOp(typesConsts_, OpConstantFalse, ops, 2);
    return id;
}

uint32_t Builder::Variable(uint32_t typePtr, uint32_t storageClass) {
    uint32_t id = NewId();
    uint32_t ops[] = { typePtr, id, storageClass };
    AppendOp(typesConsts_, OpVariable, ops, 3);
    return id;
}

uint32_t Builder::Function(uint32_t resultType, uint32_t ctrl, uint32_t typeFunction) {
    uint32_t id = NewId();
    uint32_t ops[] = { resultType, id, ctrl, typeFunction };
    AppendOp(functions_, OpFunction, ops, 4);
    return id;
}

void Builder::Label(uint32_t labelId) {
    AppendOp(functions_, OpLabel, &labelId, 1);
}

uint32_t Builder::Load(uint32_t resultType, uint32_t pointer) {
    uint32_t id = NewId();
    uint32_t ops[] = { resultType, id, pointer };
    AppendOp(functions_, OpLoad, ops, 3);
    return id;
}

void Builder::Store(uint32_t pointer, uint32_t object) {
    uint32_t ops[] = { pointer, object };
    AppendOp(functions_, OpStore, ops, 2);
}

void Builder::ReturnVoid() {
    AppendOp(functions_, OpReturn, nullptr, 0);
}

void Builder::FunctionEnd() {
    AppendOp(functions_, OpFunctionEnd, nullptr, 0);
}

uint32_t Builder::FAdd(uint32_t rt, uint32_t a, uint32_t b) {
    uint32_t id = NewId();
    uint32_t ops[] = { rt, id, a, b };
    AppendOp(functions_, OpFAdd, ops, 4);
    return id;
}
uint32_t Builder::FSub(uint32_t rt, uint32_t a, uint32_t b) {
    uint32_t id = NewId();
    uint32_t ops[] = { rt, id, a, b };
    AppendOp(functions_, OpFSub, ops, 4);
    return id;
}
uint32_t Builder::FMul(uint32_t rt, uint32_t a, uint32_t b) {
    uint32_t id = NewId();
    uint32_t ops[] = { rt, id, a, b };
    AppendOp(functions_, OpFMul, ops, 4);
    return id;
}
uint32_t Builder::Dot(uint32_t rt, uint32_t a, uint32_t b) {
    uint32_t id = NewId();
    uint32_t ops[] = { rt, id, a, b };
    AppendOp(functions_, OpDot, ops, 4);
    return id;
}

uint32_t Builder::CompositeConstruct(uint32_t rt,
                                     const uint32_t* parts, size_t partCount) {
    uint32_t id = NewId();
    std::vector<uint32_t> ops;
    ops.reserve(2 + partCount);
    ops.push_back(rt);
    ops.push_back(id);
    for (size_t i = 0; i < partCount; ++i) ops.push_back(parts[i]);
    AppendOp(functions_, OpCompositeConstruct, ops.data(), ops.size());
    return id;
}

uint32_t Builder::CompositeExtract(uint32_t rt, uint32_t composite,
                                   const uint32_t* indices, size_t indexCount) {
    uint32_t id = NewId();
    std::vector<uint32_t> ops;
    ops.reserve(3 + indexCount);
    ops.push_back(rt);
    ops.push_back(id);
    ops.push_back(composite);
    for (size_t i = 0; i < indexCount; ++i) ops.push_back(indices[i]);
    AppendOp(functions_, OpCompositeExtract, ops.data(), ops.size());
    return id;
}

uint32_t Builder::VectorShuffle(uint32_t rt,
                                uint32_t v1, uint32_t v2,
                                const uint32_t* components, size_t componentCount) {
    uint32_t id = NewId();
    std::vector<uint32_t> ops;
    ops.reserve(4 + componentCount);
    ops.push_back(rt);
    ops.push_back(id);
    ops.push_back(v1);
    ops.push_back(v2);
    for (size_t i = 0; i < componentCount; ++i) ops.push_back(components[i]);
    AppendOp(functions_, OpVectorShuffle, ops.data(), ops.size());
    return id;
}

uint32_t Builder::AccessChain(uint32_t rtPtr, uint32_t base,
                              const uint32_t* indices, size_t indexCount) {
    uint32_t id = NewId();
    std::vector<uint32_t> ops;
    ops.reserve(3 + indexCount);
    ops.push_back(rtPtr);
    ops.push_back(id);
    ops.push_back(base);
    for (size_t i = 0; i < indexCount; ++i) ops.push_back(indices[i]);
    AppendOp(functions_, OpAccessChain, ops.data(), ops.size());
    return id;
}

uint32_t Builder::AppendInFunction(uint16_t op,
                                   const uint32_t* operands, size_t operandCount) {
    AppendOp(functions_, op, operands, operandCount);
    // Caller-supplied result ID lives in operands[1] when this is a
    // value-producing instruction. We return it for convenience; for
    // void-result instructions the caller can ignore it.
    return operandCount >= 2 ? operands[1] : 0;
}

uint32_t Builder::ExtInst(uint32_t rt, uint32_t set, uint32_t instruction,
                          const uint32_t* args, size_t argCount) {
    uint32_t id = NewId();
    std::vector<uint32_t> ops;
    ops.reserve(4 + argCount);
    ops.push_back(rt);
    ops.push_back(id);
    ops.push_back(set);
    ops.push_back(instruction);
    for (size_t i = 0; i < argCount; ++i) ops.push_back(args[i]);
    AppendOp(functions_, OpExtInst, ops.data(), ops.size());
    return id;
}

std::vector<uint32_t> Builder::Finalize() const {
    std::vector<uint32_t> mod;
    mod.reserve(5 +
                capabilities_.size() + extensions_.size() + extInstImports_.size() +
                memoryModel_.size() + entryPoints_.size() + execModes_.size() +
                debug_.size() + annotations_.size() + typesConsts_.size() +
                functions_.size());

    // Header (5 words) — magic, version (1.0), generator, bound, schema.
    mod.push_back(0x07230203);
    mod.push_back(0x00010000);   // SPIR-V 1.0 — broadest Vulkan compatibility
    mod.push_back(0x00000000);   // generator = unspecified
    mod.push_back(nextId_);      // bound = max ID + 1; nextId_ already = next-free
    mod.push_back(0x00000000);   // reserved schema

    auto append = [&](const std::vector<uint32_t>& s) {
        mod.insert(mod.end(), s.begin(), s.end());
    };
    append(capabilities_);
    append(extensions_);
    append(extInstImports_);
    append(memoryModel_);
    append(entryPoints_);
    append(execModes_);
    append(debug_);
    append(annotations_);
    append(typesConsts_);
    append(functions_);
    return mod;
}

}
