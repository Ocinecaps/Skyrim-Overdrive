#include "ResourceMirror.h"
#include "DebugLogger.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <vector>
#include <cstdint>
#include <cstring>

namespace overdrive::resmirror {

namespace {

struct TextureEntry {
    uint32_t width, height, levels;
    uint32_t usage, format, pool;
};
struct BufferEntry {
    uint32_t length, usage, format_or_fvf, pool;
};
struct ShaderEntry {
    std::vector<uint32_t> bytecode;   // owned copy of dwords
};

// One mutex per table — these are creation-time only, not in the hot draw path.
std::mutex g_mTex;     std::map<void*, TextureEntry> g_tex;
std::mutex g_mVB;      std::map<void*, BufferEntry>  g_vb;
std::mutex g_mIB;      std::map<void*, BufferEntry>  g_ib;
std::mutex g_mVS;      std::map<void*, ShaderEntry>  g_vs;
std::mutex g_mPS;      std::map<void*, ShaderEntry>  g_ps;

std::atomic<uint64_t> g_totalBytecodeBytes{0};
std::chrono::steady_clock::time_point g_lastLog;

// Live translation callback — set once at install by the consumer of
// SetShaderCreatedCallback. Invoked synchronously from NoteVertex/PixelShader.
ShaderCreatedFn g_shaderCreated = nullptr;

// Heuristic for D3D9 shader bytecode length: stream of DWORDs terminated by
// 0x0000FFFF (the END token). Cap at 16K dwords as a safety belt.
size_t ScanBytecodeLen(const void* p) {
    if (!p) return 0;
    const uint32_t* d = reinterpret_cast<const uint32_t*>(p);
    size_t n = 0;
    while (d[n] != 0x0000FFFF && n < 16384) ++n;
    if (d[n] == 0x0000FFFF) ++n;   // include the END token
    return n;
}

}  // namespace

bool Install() {
    g_lastLog = std::chrono::steady_clock::now();
    OD_LOG("[ResMirror] Installed. Tracks D3D9 textures/VBs/IBs/VSs/PSs by ptr; "
           "stores VS/PS bytecode for future DXBC->SPIR-V translation.");
    return true;
}

void Shutdown() {
    // Tables auto-destruct.
}

void NoteTexture(IDirect3DTexture9* tex,
                 uint32_t width, uint32_t height, uint32_t levels,
                 uint32_t usage, uint32_t format, uint32_t pool) {
    if (!tex) return;
    std::lock_guard<std::mutex> lk(g_mTex);
    g_tex[(void*)tex] = { width, height, levels, usage, format, pool };
}

void NoteVertexBuffer(IDirect3DVertexBuffer9* vb,
                      uint32_t length, uint32_t usage, uint32_t fvf, uint32_t pool) {
    if (!vb) return;
    std::lock_guard<std::mutex> lk(g_mVB);
    g_vb[(void*)vb] = { length, usage, fvf, pool };
}

void NoteIndexBuffer(IDirect3DIndexBuffer9* ib,
                     uint32_t length, uint32_t usage, uint32_t format, uint32_t pool) {
    if (!ib) return;
    std::lock_guard<std::mutex> lk(g_mIB);
    g_ib[(void*)ib] = { length, usage, format, pool };
}

void NoteVertexShader(IDirect3DVertexShader9* sh, const void* bytecode, size_t /*bytes*/) {
    if (!sh) return;
    size_t dwords = ScanBytecodeLen(bytecode);
    ShaderEntry e;
    e.bytecode.resize(dwords);
    if (dwords) std::memcpy(e.bytecode.data(), bytecode, dwords * sizeof(uint32_t));
    g_totalBytecodeBytes.fetch_add(dwords * sizeof(uint32_t), std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lk(g_mVS);
        g_vs[(void*)sh] = std::move(e);
    }
    // Fire the live-translation callback OUTSIDE the lock so the consumer
    // can do expensive work (vkCreateShaderModule) without blocking other
    // creators. We pass a const pointer into the just-stored bytecode —
    // the callback uses it synchronously and returns; no lifetime hazard.
    if (g_shaderCreated && dwords > 0) {
        std::lock_guard<std::mutex> lk(g_mVS);
        auto it = g_vs.find((void*)sh);
        if (it != g_vs.end()) {
            g_shaderCreated((void*)sh, it->second.bytecode.data(),
                            it->second.bytecode.size(), false);
        }
    }
}

void NotePixelShader(IDirect3DPixelShader9* sh, const void* bytecode, size_t /*bytes*/) {
    if (!sh) return;
    size_t dwords = ScanBytecodeLen(bytecode);
    ShaderEntry e;
    e.bytecode.resize(dwords);
    if (dwords) std::memcpy(e.bytecode.data(), bytecode, dwords * sizeof(uint32_t));
    g_totalBytecodeBytes.fetch_add(dwords * sizeof(uint32_t), std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lk(g_mPS);
        g_ps[(void*)sh] = std::move(e);
    }
    if (g_shaderCreated && dwords > 0) {
        std::lock_guard<std::mutex> lk(g_mPS);
        auto it = g_ps.find((void*)sh);
        if (it != g_ps.end()) {
            g_shaderCreated((void*)sh, it->second.bytecode.data(),
                            it->second.bytecode.size(), true);
        }
    }
}

void SetShaderCreatedCallback(ShaderCreatedFn cb) {
    g_shaderCreated = cb;
}

void ForEachVertexShader(ShaderVisitor cb, void* user) {
    std::lock_guard<std::mutex> lk(g_mVS);
    for (auto& kv : g_vs) {
        cb(kv.first, kv.second.bytecode.data(), kv.second.bytecode.size(), user);
    }
}

void ForEachPixelShader(ShaderVisitor cb, void* user) {
    std::lock_guard<std::mutex> lk(g_mPS);
    for (auto& kv : g_ps) {
        cb(kv.first, kv.second.bytecode.data(), kv.second.bytecode.size(), user);
    }
}

void MaybeLogStats() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog);
    if (elapsed.count() < 5000) return;
    g_lastLog = now;

    size_t nTex, nVB, nIB, nVS, nPS;
    { std::lock_guard<std::mutex> lk(g_mTex); nTex = g_tex.size(); }
    { std::lock_guard<std::mutex> lk(g_mVB);  nVB  = g_vb.size();  }
    { std::lock_guard<std::mutex> lk(g_mIB);  nIB  = g_ib.size();  }
    { std::lock_guard<std::mutex> lk(g_mVS);  nVS  = g_vs.size();  }
    { std::lock_guard<std::mutex> lk(g_mPS);  nPS  = g_ps.size();  }
    uint64_t bcBytes = g_totalBytecodeBytes.load(std::memory_order_relaxed);

    OD_LOG("[ResMirror] tracked: tex=%zu vb=%zu ib=%zu vs=%zu ps=%zu | "
           "shader bytecode total = %llu bytes (%.1f KB)",
           nTex, nVB, nIB, nVS, nPS,
           (unsigned long long)bcBytes, bcBytes / 1024.0);
}

}
