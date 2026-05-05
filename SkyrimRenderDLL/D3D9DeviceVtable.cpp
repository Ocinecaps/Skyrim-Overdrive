#include "D3D9DeviceVtable.h"
#include "DebugLogger.h"

#include <windows.h>
#include <d3d9.h>
#include <algorithm>
#include <chrono>
#include <cstring>

namespace overdrive::d3d9vt {

std::atomic<uint32_t> gCounters[kNumSlots] = {};

// Slot names mirror the order in d3d9.h's IDirect3DDevice9Vtbl declaration.
// Slots 0..2 are IUnknown (QueryInterface / AddRef / Release).
// Slots 3..118 are IDirect3DDevice9-specific.
const char* kSlotNames[kNumSlots] = {
    "QueryInterface", "AddRef", "Release",                            // 0..2
    "TestCooperativeLevel", "GetAvailableTextureMem",
    "EvictManagedResources", "GetDirect3D",                           // 3..6
    "GetDeviceCaps", "GetDisplayMode", "GetCreationParameters",       // 7..9
    "SetCursorProperties", "SetCursorPosition", "ShowCursor",         // 10..12
    "CreateAdditionalSwapChain", "GetSwapChain", "GetNumberOfSwapChains",
    "Reset", "Present", "GetBackBuffer", "GetRasterStatus",           // 16..19
    "SetDialogBoxMode", "SetGammaRamp", "GetGammaRamp",               // 20..22
    "CreateTexture", "CreateVolumeTexture", "CreateCubeTexture",      // 23..25
    "CreateVertexBuffer", "CreateIndexBuffer",                        // 26..27
    "CreateRenderTarget", "CreateDepthStencilSurface",                // 28..29
    "UpdateSurface", "UpdateTexture", "GetRenderTargetData",          // 30..32
    "GetFrontBufferData", "StretchRect", "ColorFill",                 // 33..35
    "CreateOffscreenPlainSurface",                                    // 36
    "SetRenderTarget", "GetRenderTarget",                             // 37..38
    "SetDepthStencilSurface", "GetDepthStencilSurface",               // 39..40
    "BeginScene", "EndScene", "Clear",                                // 41..43
    "SetTransform", "GetTransform", "MultiplyTransform",              // 44..46
    "SetViewport", "GetViewport",                                     // 47..48
    "SetMaterial", "GetMaterial",                                     // 49..50
    "SetLight", "GetLight", "LightEnable", "GetLightEnable",          // 51..54
    "SetClipPlane", "GetClipPlane",                                   // 55..56
    "SetRenderState", "GetRenderState",                               // 57..58
    "CreateStateBlock", "BeginStateBlock", "EndStateBlock",           // 59..61
    "SetClipStatus", "GetClipStatus",                                 // 62..63
    "GetTexture", "SetTexture",                                       // 64..65
    "GetTextureStageState", "SetTextureStageState",                   // 66..67
    "GetSamplerState", "SetSamplerState",                             // 68..69
    "ValidateDevice",                                                 // 70
    "SetPaletteEntries", "GetPaletteEntries",                         // 71..72
    "SetCurrentTexturePalette", "GetCurrentTexturePalette",           // 73..74
    "SetScissorRect", "GetScissorRect",                               // 75..76
    "SetSoftwareVertexProcessing", "GetSoftwareVertexProcessing",     // 77..78
    "SetNPatchMode", "GetNPatchMode",                                 // 79..80
    "DrawPrimitive", "DrawIndexedPrimitive",                          // 81..82
    "DrawPrimitiveUP", "DrawIndexedPrimitiveUP",                      // 83..84
    "ProcessVertices",                                                // 85
    "CreateVertexDeclaration", "SetVertexDeclaration", "GetVertexDeclaration",
    "SetFVF", "GetFVF",                                               // 89..90
    "CreateVertexShader", "SetVertexShader", "GetVertexShader",       // 91..93
    "SetVertexShaderConstantF", "GetVertexShaderConstantF",           // 94..95
    "SetVertexShaderConstantI", "GetVertexShaderConstantI",           // 96..97
    "SetVertexShaderConstantB", "GetVertexShaderConstantB",           // 98..99
    "SetStreamSource", "GetStreamSource",                             // 100..101
    "SetStreamSourceFreq", "GetStreamSourceFreq",                     // 102..103
    "SetIndices", "GetIndices",                                       // 104..105
    "CreatePixelShader", "SetPixelShader", "GetPixelShader",          // 106..108
    "SetPixelShaderConstantF", "GetPixelShaderConstantF",             // 109..110
    "SetPixelShaderConstantI", "GetPixelShaderConstantI",             // 111..112
    "SetPixelShaderConstantB", "GetPixelShaderConstantB",             // 113..114
    "DrawRectPatch", "DrawTriPatch", "DeletePatch",                   // 115..117
    "CreateQuery"                                                      // 118
};

// Originals exposed publicly so D3D9Mirror's typed wrappers can chain to the
// real D3D9 implementation by index. Thunks JMP through dword ptr [&gOriginals[slot]],
// and typed wrappers use the same array when calling the original function.
void* gOriginals[kNumSlots] = {};

namespace {

constexpr int kSlot_Present  = 17;   // skipped — D3D9Hook owns this slot

BYTE*  g_thunkPool              = nullptr;
size_t g_thunkPoolSize          = 0;
bool   g_installed              = false;

constexpr size_t kThunkBytes = 15;  // see ThunkLayout in BulkHookDevice

// One-shot stats state.
std::chrono::steady_clock::time_point g_lastLog;
uint32_t g_lastSnap[kNumSlots] = {};

}  // namespace

bool BulkHookDevice(IDirect3DDevice9* dev) {
    if (g_installed) return true;
    if (!dev) {
        OD_LOG("[D3D9VT] BulkHookDevice: device is null");
        return false;
    }

    // Allocate one page of executable memory for all thunks.
    // 119 × 15 = 1785 bytes; one 4 KB page is plenty.
    g_thunkPoolSize = 4096;
    g_thunkPool = static_cast<BYTE*>(VirtualAlloc(
        nullptr, g_thunkPoolSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!g_thunkPool) {
        OD_LOG("[D3D9VT] VirtualAlloc(%u, RWE) failed: GetLastError=%lu",
               (unsigned)g_thunkPoolSize, GetLastError());
        return false;
    }
    memset(g_thunkPool, 0xCC, g_thunkPoolSize);  // INT3-pad unused tail

    void** vtable = *reinterpret_cast<void***>(dev);

    // Make the vtable writable for the patch.
    DWORD oldProtect = 0;
    if (!VirtualProtect(vtable, kNumSlots * sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        OD_LOG("[D3D9VT] VirtualProtect on vtable failed: GetLastError=%lu", GetLastError());
        return false;
    }

    int hooked  = 0;
    int skipped = 0;
    BYTE* code  = g_thunkPool;
    for (int slot = 0; slot < kNumSlots; ++slot) {
        // Capture the original pointer regardless — even for the skipped
        // slot — so a future Phase can chain through it if it wants.
        gOriginals[slot] = vtable[slot];

        if (slot == kSlot_Present) {
            ++skipped;
            continue;
        }

        // Generate a fresh 15-byte counting-passthrough thunk for this slot.
        //
        //   50                  push eax
        //   F0 FF 05 <imm32>    lock inc dword ptr [&gCounters[slot]]   (7 B)
        //   58                  pop eax
        //   FF 25 <imm32>       jmp  dword ptr [&gOriginals[slot]]     (6 B)
        //
        // We use `lock inc dword` (not qword) because counters are atomic uint64
        // but x86 `lock inc` on the lower 32 bits is sufficient for our purposes
        // (~4 billion calls before the low half wraps, ~7 hours @ 162k/s).
        BYTE* const thunkStart = code;
        *code++ = 0x50;                                          // push eax
        *code++ = 0xF0; *code++ = 0xFF; *code++ = 0x05;          // lock inc dword [imm32]
        *reinterpret_cast<DWORD*>(code) = reinterpret_cast<DWORD>(&gCounters[slot]);
        code += 4;
        *code++ = 0x58;                                          // pop eax
        *code++ = 0xFF; *code++ = 0x25;                          // jmp dword [imm32]
        *reinterpret_cast<DWORD*>(code) = reinterpret_cast<DWORD>(&gOriginals[slot]);
        code += 4;

        vtable[slot] = thunkStart;
        ++hooked;
    }

    VirtualProtect(vtable, kNumSlots * sizeof(void*), oldProtect, &oldProtect);
    g_installed = true;
    g_lastLog = std::chrono::steady_clock::now();

    OD_LOG("[D3D9VT] Bulk-hooked IDirect3DDevice9: %d slots counting, %d skipped (Present). "
           "Thunk pool @ %p (%u bytes used).",
           hooked, skipped, g_thunkPool, (unsigned)(code - g_thunkPool));
    return true;
}

bool ReplaceSlot(IDirect3DDevice9* dev, int slot, void* newFn) {
    if (!dev || slot < 0 || slot >= kNumSlots || !newFn) return false;
    void** vtable = *reinterpret_cast<void***>(dev);
    DWORD oldProtect = 0;
    if (!VirtualProtect(&vtable[slot], sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        return false;
    }
    vtable[slot] = newFn;
    VirtualProtect(&vtable[slot], sizeof(void*), oldProtect, &oldProtect);
    return true;
}

void MaybeLogStats() {
    if (!g_installed) return;

    const auto now     = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog);
    if (elapsed.count() < 5000) return;
    g_lastLog = now;

    struct SlotRate { int idx; uint32_t total; uint32_t delta; };
    SlotRate active[kNumSlots];
    int activeCount = 0;
    for (int i = 0; i < kNumSlots; ++i) {
        const uint32_t cur = gCounters[i].load(std::memory_order_relaxed);
        const uint32_t d   = cur - g_lastSnap[i];
        g_lastSnap[i] = cur;
        if (d > 0 || cur > 0) {
            active[activeCount++] = { i, cur, d };
        }
    }

    std::sort(active, active + activeCount,
              [](const SlotRate& a, const SlotRate& b) { return a.delta > b.delta; });

    const double secs = elapsed.count() / 1000.0;
    OD_LOG("[D3D9VT] last %.1fs: %d active slots out of %d. Top 10 by rate:",
           secs, activeCount, kNumSlots);
    const int topN = activeCount < 10 ? activeCount : 10;
    for (int i = 0; i < topN; ++i) {
        OD_LOG("[D3D9VT]   [%3d] %-30s = %llu (+%.0f/s)",
               active[i].idx, kSlotNames[active[i].idx],
               (unsigned long long)active[i].total,
               (double)active[i].delta / secs);
    }
}

}  // namespace overdrive::d3d9vt
