#pragma once
#include <cstdint>
#include <cstddef>

struct IDirect3DTexture9;
struct IDirect3DVertexBuffer9;
struct IDirect3DIndexBuffer9;
struct IDirect3DVertexShader9;
struct IDirect3DPixelShader9;

namespace overdrive::resmirror {

// =============================================================================
// ResourceMirror — persistent metadata & shader bytecode store
// =============================================================================
//
// At each D3D9 CreateXxx call, we insert a record into the appropriate table
// keyed by the D3D9 object pointer. Stores enough info to later allocate a
// matching Vulkan resource:
//
//   Textures: width, height, levels, format, pool, usage
//   VertexBuffers: length, FVF, pool, usage
//   IndexBuffers: length, format, pool, usage
//   VertexShaders: bytecode copy (so we can DXBC→SPIR-V translate later)
//   PixelShaders:  bytecode copy
//
// Lookup is O(log N) via std::map under a per-table mutex. Insert/lookup
// throughput required is well below 10k/s (resource creation is rare relative
// to draws), so coarse locking is fine.
//
// The shader bytecode is copied once at creation. Each entry holds its own
// std::vector<uint32_t>. Total memory is bounded: Skyrim creates ~900 vertex
// shaders + ~250 pixel shaders, average ~200 dwords each = ~1 MB total.
//
// Future Vulkan-side fields (added in later phases):
//   Texture::vkImage, Texture::vkImageView, Texture::vkMemory
//   {VB,IB}::vkBuffer, ::vkMemory
//   {VS,PS}::spirv, ::vkShaderModule

bool Install();
void Shutdown();

void NoteTexture(IDirect3DTexture9* tex,
                 uint32_t width, uint32_t height, uint32_t levels,
                 uint32_t usage, uint32_t format, uint32_t pool);
void NoteVertexBuffer(IDirect3DVertexBuffer9* vb,
                      uint32_t length, uint32_t usage, uint32_t fvf, uint32_t pool);
void NoteIndexBuffer(IDirect3DIndexBuffer9* ib,
                     uint32_t length, uint32_t usage, uint32_t format, uint32_t pool);
void NoteVertexShader(IDirect3DVertexShader9* sh, const void* bytecode, size_t bytes);
void NotePixelShader(IDirect3DPixelShader9* sh,  const void* bytecode, size_t bytes);

// Throttled internally (5s) — logs counts & total bytecode memory.
void MaybeLogStats();

// Snapshot iteration for analyzers. The callback is invoked for every
// captured shader of the given type. The bytecode pointer + dword count
// are valid only for the duration of the call (held under table lock).
// Don't perform expensive work or call back into ResourceMirror inside
// the callback.
using ShaderVisitor = void(*)(const void* d3d9Ptr,
                              const uint32_t* bytecode, size_t dwords,
                              void* user);
void ForEachVertexShader(ShaderVisitor cb, void* user);
void ForEachPixelShader(ShaderVisitor cb, void* user);

// =============================================================================
// Live translation hooks — Phase B multi-core rendering prep
// =============================================================================
//
// The first time a D3D9 shader is touched, we want to translate its bytecode
// to SPIR-V and create a VkShaderModule. The translated modules are the input
// to VkPipeline creation later. Doing this eagerly at shader-create time
// (rather than at first-bind) keeps the per-frame hot path free of one-time
// translation work — when the translator lands per-frame, every shader is
// already cached.
//
// The notify callback is invoked from inside Note{Vertex,Pixel}Shader after
// the bytecode is stored. It runs synchronously — keep it cheap, or defer
// to a worker.
using ShaderCreatedFn = void(*)(const void* d3d9Ptr,
                                const uint32_t* bytecode, size_t dwords,
                                bool isPixelShader);
void SetShaderCreatedCallback(ShaderCreatedFn cb);

}
