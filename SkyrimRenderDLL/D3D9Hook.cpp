#include "D3D9Hook.h"
#include "DebugLogger.h"
#include "MinHook/MinHook.h"
#include "D3D9DeviceVtable.h"
#include "D3D9Mirror.h"
#include "D3D9PipelineDispatcher.h"

#include <windows.h>
#include <psapi.h>
#include <d3d9.h>
#include <cstring>
#include <mutex>

namespace overdrive::d3d9hook {

std::atomic<unsigned long long> gPresentCount{0};
std::atomic<unsigned long long> gCreateDeviceCount{0};
std::atomic<unsigned long long> gDirect3DCreate9Count{0};
std::atomic<IDirect3DDevice9*>  gDevice{nullptr};
std::atomic<unsigned int>       gBackBufferWidth{0};
std::atomic<unsigned int>       gBackBufferHeight{0};
std::atomic<unsigned long>      gRenderThreadId{0};
std::atomic<void*>              gRenderThreadHandle{nullptr};

// ENB-bypass fix support — defined after the slot-globals anonymous
// namespace at the bottom of the file. Forward-declared here so
// HookedCreateDevice (in the upper anonymous namespace) can call them.
// `static` gives internal linkage; visibility is via the implicit
// using-directive that anonymous namespaces inject into the enclosing
// scope.
static void TryHookEmbeddedRealDevice(IDirect3DDevice9* wrapped);

namespace {

constexpr int kVtbl_IDirect3D9_CreateDevice         = 16;
constexpr int kVtbl_IDirect3DDevice9_Present        = 17;

using PFN_Direct3DCreate9 = IDirect3D9* (WINAPI*)(UINT);
using PFN_CreateDevice    = HRESULT (STDMETHODCALLTYPE*)(IDirect3D9*, UINT, D3DDEVTYPE,
                                                         HWND, DWORD,
                                                         D3DPRESENT_PARAMETERS*,
                                                         IDirect3DDevice9**);
using PFN_Present         = HRESULT (STDMETHODCALLTYPE*)(IDirect3DDevice9*,
                                                         const RECT*, const RECT*,
                                                         HWND, const RGNDATA*);

PFN_Direct3DCreate9 g_origDirect3DCreate9 = nullptr;
PFN_CreateDevice    g_origCreateDevice    = nullptr;
PFN_Present         g_origPresent         = nullptr;

// ---------- Phase 2.5: back buffer capture state ----------

// Persistent system-memory staging surface, recreated when back buffer
// dimensions/format change. Resides in D3DPOOL_SYSTEMMEM so LockRect on it
// is fast (no GPU sync).
IDirect3DSurface9* g_staging        = nullptr;
unsigned           g_stagingWidth   = 0;
unsigned           g_stagingHeight  = 0;
D3DFORMAT          g_stagingFormat  = D3DFMT_UNKNOWN;

// Triple-buffered ring of captured frames. Writer (Skyrim's render thread)
// picks a slot != latest-read; reader (our worker thread) reads latest.
// Per-slot mutex protects the slot during memcpy.
constexpr int  kRingSlots = 3;
CapturedFrame  g_ring[kRingSlots];
std::mutex     g_ringMu[kRingSlots];
std::atomic<int> g_ringWriteCursor{0};   // monotonic; modulo gives next write slot
std::atomic<int> g_ringLatestRead{-1};   // -1 == nothing captured yet

// Counters separate from gPresentCount so we can log capture-specific events.
std::atomic<unsigned long long> g_captureOk{0};
std::atomic<unsigned long long> g_captureFail{0};

// User asked us to drop the visible-window apparatus — we're not displaying
// captured frames anywhere anymore, so spending a 6.6-20 MB GPU→CPU readback
// per frame is pure waste. Frame capture is now OFF by default; flip back
// when re-enabling overlay/HUD work in the future.
constexpr bool                  kFrameCaptureEnabled    = false;
constexpr unsigned long long    kCaptureEveryNthPresent = 3;

bool VtableHook(void* comObj, int slot, void* newFunc, void** outOrig) {
    if (!comObj) return false;
    auto vtable = *reinterpret_cast<void***>(comObj);
    DWORD oldProtect = 0;
    if (!VirtualProtect(&vtable[slot], sizeof(void*), PAGE_READWRITE, &oldProtect)) return false;
    *outOrig = vtable[slot];
    vtable[slot] = newFunc;
    VirtualProtect(&vtable[slot], sizeof(void*), oldProtect, &oldProtect);
    return true;
}

// Ensure g_staging exists with matching format/dims. Lazy alloc on first call
// or whenever the back buffer dimensions change (e.g., resolution change,
// fullscreen toggle, ENB resize).
bool EnsureStagingSurface(IDirect3DDevice9* dev, const D3DSURFACE_DESC& desc) {
    if (g_staging &&
        g_stagingWidth  == desc.Width  &&
        g_stagingHeight == desc.Height &&
        g_stagingFormat == desc.Format) {
        return true;
    }
    if (g_staging) {
        g_staging->Release();
        g_staging = nullptr;
    }
    HRESULT hr = dev->CreateOffscreenPlainSurface(
        desc.Width, desc.Height, desc.Format, D3DPOOL_SYSTEMMEM, &g_staging, nullptr);
    if (FAILED(hr) || !g_staging) {
        OD_LOG("[D3D9] CreateOffscreenPlainSurface(%ux%u fmt=%u) failed hr=0x%08X",
               desc.Width, desc.Height, (unsigned)desc.Format, (unsigned)hr);
        g_staging = nullptr;
        return false;
    }
    g_stagingWidth  = desc.Width;
    g_stagingHeight = desc.Height;
    g_stagingFormat = desc.Format;
    OD_LOG("[D3D9] Staging surface ready: %ux%u fmt=%u",
           desc.Width, desc.Height, (unsigned)desc.Format);
    return true;
}

// Capture the back buffer for this frame. Called BEFORE g_origPresent so the
// back buffer contents are still defined (D3DSWAPEFFECT_DISCARD invalidates
// them after Present).
void CaptureBackBuffer(IDirect3DDevice9* dev, unsigned long long frameIndex) {
    IDirect3DSurface9* back = nullptr;
    if (FAILED(dev->GetRenderTarget(0, &back)) || !back) {
        g_captureFail.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    D3DSURFACE_DESC desc{};
    back->GetDesc(&desc);

    if (!EnsureStagingSurface(dev, desc)) {
        back->Release();
        g_captureFail.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Asynchronous GPU→CPU copy. Slow (~10–20 MB at 3440x1440) but unavoidable
    // for screen capture. Phase 2.9 will look at throttling / async pipelines
    // if perf becomes a problem.
    HRESULT hr = dev->GetRenderTargetData(back, g_staging);
    back->Release();
    if (FAILED(hr)) {
        g_captureFail.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    D3DLOCKED_RECT lr{};
    if (FAILED(g_staging->LockRect(&lr, nullptr, D3DLOCK_READONLY))) {
        g_captureFail.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Pick a ring slot that isn't the latest-read (so the reader can keep
    // holding a stale read while we write). 3 slots = 1 in-flight read +
    // 1 newest + 1 spare.
    int writeIdx = g_ringWriteCursor.fetch_add(1, std::memory_order_relaxed) % kRingSlots;
    int latest   = g_ringLatestRead.load(std::memory_order_relaxed);
    if (writeIdx == latest) {
        writeIdx = (writeIdx + 1) % kRingSlots;
    }

    {
        std::lock_guard<std::mutex> lk(g_ringMu[writeIdx]);
        CapturedFrame& slot = g_ring[writeIdx];
        slot.width      = desc.Width;
        slot.height     = desc.Height;
        slot.format     = static_cast<unsigned>(desc.Format);
        slot.frameIndex = frameIndex;
        // Tightly pack rows (drop pitch padding) so the consumer can hand the
        // buffer straight to vkCmdCopyBufferToImage with no per-row work.
        const size_t bpp      = 4;  // X8R8G8B8 / A8R8G8B8 — both 4 bytes
        const size_t rowBytes = static_cast<size_t>(desc.Width) * bpp;
        slot.pixels.resize(rowBytes * desc.Height);
        const unsigned char* src = static_cast<const unsigned char*>(lr.pBits);
        unsigned char*       dst = slot.pixels.data();
        for (unsigned y = 0; y < desc.Height; ++y) {
            memcpy(dst, src, rowBytes);
            src += lr.Pitch;
            dst += rowBytes;
        }
    }
    g_staging->UnlockRect();
    g_ringLatestRead.store(writeIdx, std::memory_order_release);

    auto ok = g_captureOk.fetch_add(1, std::memory_order_relaxed) + 1;
    if (ok == 1 || ok == 60 || ok == 600 || (ok % 6000) == 0) {
        // Hash a few bytes from the captured pixels just to prove the data is
        // actually changing (not stuck on one frame).
        unsigned int sig = 0;
        for (int i = 0; i < 16 && i < (int)g_ring[writeIdx].pixels.size(); ++i) {
            sig = (sig * 31u) + g_ring[writeIdx].pixels[i];
        }
        OD_LOG("[D3D9] Captured #%llu: %ux%u fmt=%u slot=%d frame=%llu sig=0x%08X",
               ok, desc.Width, desc.Height, (unsigned)desc.Format,
               writeIdx, frameIndex, sig);
    }
}

HRESULT STDMETHODCALLTYPE HookedPresent(IDirect3DDevice9* dev,
                                        const RECT* sourceRect,
                                        const RECT* destRect,
                                        HWND destWindowOverride,
                                        const RGNDATA* dirtyRegion) {
    auto count = gPresentCount.fetch_add(1, std::memory_order_relaxed) + 1;
    if (count == 1 || count == 10 || count == 100 || count == 1000 ||
        count == 10000 || (count % 60000) == 0) {
        OD_LOG("[D3D9] Present #%llu (dev=%p)", count, dev);
    }

    // First Present call: this thread IS Skyrim's render thread. Open a handle
    // for the EIP-sampling profiler. Done lock-free via CAS so concurrent
    // first-callers (shouldn't happen) only set it once.
    if (gRenderThreadId.load(std::memory_order_relaxed) == 0) {
        DWORD tid = GetCurrentThreadId();
        unsigned long expected = 0;
        if (gRenderThreadId.compare_exchange_strong(expected, tid,
                std::memory_order_acq_rel)) {
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                  THREAD_QUERY_INFORMATION,
                                  FALSE, tid);
            if (h) {
                gRenderThreadHandle.store(h, std::memory_order_release);
                OD_LOG("[D3D9] Captured render thread tid=%lu handle=%p", tid, h);
            } else {
                OD_LOG("[D3D9] OpenThread(tid=%lu) failed: %lu", tid, GetLastError());
            }
        }
    }

    // Frame capture currently disabled (kFrameCaptureEnabled). When it ran,
    // GetRenderTargetData's GPU→CPU copy was the dominant per-frame cost.
    if (kFrameCaptureEnabled && (count % kCaptureEveryNthPresent) == 0) {
        CaptureBackBuffer(dev, count);
    }

    // Stage 2 pipeline: drain any deferred ops (Mirror_Draw* enqueues into
    // the pipeline buffer) before calling real Present. Otherwise the GPU
    // never sees this frame's draws. Flush blocks T_record until T_dispatch
    // has caught up — pipeline parallelism within Stage 2 is limited to
    // "T_dispatch has been issuing draws while T_record was building the
    // frame", but the Flush at Present is a sync point.
    //
    // Stage 5 will replace this with a deferred-Present model where Present
    // itself enqueues onto the pipeline; the dispatcher calls real Present
    // asynchronously, eliminating this sync point and giving full 1-frame
    // pipeline parallelism.
    if (pipeline::IsActive()) {
        pipeline::Flush();
    }

    return g_origPresent(dev, sourceRect, destRect, destWindowOverride, dirtyRegion);
}

HRESULT STDMETHODCALLTYPE HookedCreateDevice(IDirect3D9* d3d, UINT adapter,
                                             D3DDEVTYPE devType, HWND focusHwnd,
                                             DWORD behaviorFlags,
                                             D3DPRESENT_PARAMETERS* pp,
                                             IDirect3DDevice9** outDev) {
    HRESULT hr = g_origCreateDevice(d3d, adapter, devType, focusHwnd,
                                    behaviorFlags, pp, outDev);
    auto count = gCreateDeviceCount.fetch_add(1, std::memory_order_relaxed) + 1;

    OD_LOG("[D3D9] CreateDevice #%llu hr=0x%08X dev=%p adapter=%u type=%d focus=%p flags=0x%08X",
        count, hr, (outDev ? *outDev : nullptr), adapter, devType, focusHwnd, behaviorFlags);
    // Decode behavior flags — D3DCREATE_MULTITHREADED is the interesting one
    // because it tells us we can safely call device methods from worker
    // threads (D3D9 runtime adds internal locks). Skyrim's value is 0x54.
    OD_LOG("[D3D9]   Flags decoded: %s%s%s%s%s%s",
        (behaviorFlags & 0x00000002) ? "FPU_PRESERVE " : "",
        (behaviorFlags & 0x00000004) ? "MULTITHREADED " : "",
        (behaviorFlags & 0x00000010) ? "PUREDEVICE " : "",
        (behaviorFlags & 0x00000020) ? "SOFTWARE_VP " : "",
        (behaviorFlags & 0x00000040) ? "HARDWARE_VP " : "",
        (behaviorFlags & 0x00000080) ? "MIXED_VP " : "");
    if (pp) {
        OD_LOG("[D3D9]   PP: BackBuffer %ux%u fmt=%d count=%u, MultiSample=%d, SwapEffect=%d, "
               "Windowed=%d, EnableAutoDepthStencil=%d, AutoDepthFmt=%d, Flags=0x%08X, "
               "FullScreenRefreshHz=%u, PresentationInterval=0x%08X",
            pp->BackBufferWidth, pp->BackBufferHeight, pp->BackBufferFormat,
            pp->BackBufferCount, pp->MultiSampleType, pp->SwapEffect,
            pp->Windowed, pp->EnableAutoDepthStencil, pp->AutoDepthStencilFormat,
            pp->Flags, pp->FullScreen_RefreshRateInHz, pp->PresentationInterval);
        gBackBufferWidth.store(pp->BackBufferWidth, std::memory_order_relaxed);
        gBackBufferHeight.store(pp->BackBufferHeight, std::memory_order_relaxed);
    }

    if (SUCCEEDED(hr) && outDev && *outDev) {
        gDevice.store(*outDev, std::memory_order_release);

        // Phase 5: bulk-hook ALL 119 IDirect3DDevice9 vtable slots first
        // (slot 17 / Present is intentionally skipped so D3D9Hook keeps
        // ownership of the capture path). Order matters: the bulk hook
        // captures the original Present pointer into d3d9vt::gOriginals[17],
        // then the specialized Present hook below overwrites slot 17 with
        // HookedPresent and saves the (still-original) Present pointer into
        // g_origPresent. The bulk-saved Present pointer is unused; harmless.
        d3d9vt::BulkHookDevice(*outDev);

        // Phase 6: replace selected vtable slots with TYPED C++ wrappers.
        // These chain to the original D3D9 method via d3d9vt::gOriginals[slot]
        // so the game still renders via D3D9, but our Vulkan-side mirror state
        // catches up to know what the renderer is doing. Future phases will
        // progressively replace each wrapper's body with Vulkan command emission.
        mirror::Install(*outDev);

        if (g_origPresent == nullptr) {
            if (VtableHook(*outDev, kVtbl_IDirect3DDevice9_Present,
                           reinterpret_cast<void*>(HookedPresent),
                           reinterpret_cast<void**>(&g_origPresent))) {
                OD_LOG("[D3D9] IDirect3DDevice9::Present hooked at vtable[%d] (orig=%p)",
                    kVtbl_IDirect3DDevice9_Present, g_origPresent);
            } else {
                OD_LOG("[D3D9] IDirect3DDevice9::Present vtable hook FAILED");
            }
        }

        // ENB BYPASS FIX: probe the device we got back for an embedded
        // pointer to a SECOND IDirect3DDevice9. ENB's wrapper class
        // typically inherits IDirect3DDevice9 (so first member at +0 is
        // its own vtable) and stores the underlying real device pointer
        // at a low offset (+4..+0x40). When ENB internally needs to read
        // device state during its post-process passes, it bypasses its
        // own wrapper and calls methods directly on that saved real
        // device pointer — those calls miss our hooks unless we ALSO
        // modify the real device's vtable.
        //
        // Heuristic: walk *(void**)(*outDev + offset) for offset = 4..0x40,
        // step 4. For each candidate pointer P that's:
        //   1. non-null and points to readable committed memory
        //   2. P[0] (its vtable) points into a known d3d9.dll module's
        //      address range
        //   3. P[0][0] (first vtable entry, IUnknown::QueryInterface) is
        //      a code address in the same d3d9.dll module
        // ...P is almost certainly a real IDirect3DDevice9. Apply the
        // same bulk-hook + Mirror::Install + Present hook to it.
        TryHookEmbeddedRealDevice(*outDev);
    }
    return hr;
}

IDirect3D9* WINAPI HookedDirect3DCreate9(UINT sdkVersion) {
    IDirect3D9* d3d = g_origDirect3DCreate9 ? g_origDirect3DCreate9(sdkVersion) : nullptr;
    auto count = gDirect3DCreate9Count.fetch_add(1, std::memory_order_relaxed) + 1;
    OD_LOG("[D3D9] Direct3DCreate9 #%llu (sdk=%u) -> %p", count, sdkVersion, d3d);

    if (d3d && g_origCreateDevice == nullptr) {
        if (VtableHook(d3d, kVtbl_IDirect3D9_CreateDevice,
                       reinterpret_cast<void*>(HookedCreateDevice),
                       reinterpret_cast<void**>(&g_origCreateDevice))) {
            OD_LOG("[D3D9] IDirect3D9::CreateDevice hooked at vtable[%d] (orig=%p)",
                kVtbl_IDirect3D9_CreateDevice, g_origCreateDevice);
        } else {
            OD_LOG("[D3D9] IDirect3D9::CreateDevice vtable hook FAILED");
        }
    }
    return d3d;
}

}  // namespace

bool TryGetLatestFrame(CapturedFrame& out, unsigned long long& inOutLastSeen) {
    int idx = g_ringLatestRead.load(std::memory_order_acquire);
    if (idx < 0) return false;
    std::lock_guard<std::mutex> lk(g_ringMu[idx]);
    const CapturedFrame& src = g_ring[idx];
    if (src.frameIndex == inOutLastSeen) return false;
    out = src;  // copies vector
    inOutLastSeen = src.frameIndex;
    return true;
}

// =============================================================================
// Multi-module Direct3DCreate9 hook
// =============================================================================
// ENB's d3d9.dll proxy is what Skyrim resolves "d3d9" to. Hooking only that
// module catches Skyrim's Direct3DCreate9 call (which lands in ENB), but ENB
// internally calls the REAL d3d9.dll's Direct3DCreate9 — which we never see.
// Result: the real IDirect3D9 / IDirect3DDevice9 vtables are never modified,
// and every internal ENB read bypasses our Mirror shadow.
//
// Fix: walk all loaded modules, find every one whose filename is "d3d9.dll"
// (case-insensitive), hook each one's Direct3DCreate9 export. Skyrim's call
// to ENB-d3d9 fires our hook; ENB's call to real-d3d9 ALSO fires our hook.
// Both paths funnel through HookedDirect3DCreate9 → both IDirect3D9 instances
// (wrapper and real) get their CreateDevice vtable hooked → both eventual
// devices get bulk-hooked + Mirror::Install'd.
//
// Up to 4 d3d9 modules tracked (ENB proxy + system32 real + ReShade + spare).
// Each gets its own MinHook trampoline so the call chain is clean.

namespace {

constexpr int kMaxD3d9Modules = 4;

struct D3D9HookSlot {
    HMODULE             module    = nullptr;
    char                path[260] = {};
    LPVOID              target    = nullptr;
    PFN_Direct3DCreate9 origTramp = nullptr;
};

D3D9HookSlot g_d3d9Slots[kMaxD3d9Modules];
int          g_d3d9SlotCount = 0;

// Per-slot trampoline: each goes to the same HookedDirect3DCreate9 logic.
// We need a unique HookedXxx per slot because MinHook stores the original
// trampoline per hook, and HookedDirect3DCreate9 must call back through
// the matching trampoline so the chain reaches the next-lower module.
// Generate them via macro.
#define DEFINE_HOOKED_SLOT(N) \
    IDirect3D9* WINAPI HookedDirect3DCreate9_Slot##N(UINT sdkVersion) {                     \
        IDirect3D9* d3d = g_d3d9Slots[N].origTramp ? g_d3d9Slots[N].origTramp(sdkVersion) : nullptr; \
        const auto count = gDirect3DCreate9Count.fetch_add(1, std::memory_order_relaxed) + 1; \
        OD_LOG("[D3D9] Direct3DCreate9 #%llu via slot[%d]=%s (sdk=%u) -> %p",                \
               count, N, g_d3d9Slots[N].path, sdkVersion, d3d);                              \
        if (d3d && g_origCreateDevice == nullptr) {                                          \
            if (VtableHook(d3d, kVtbl_IDirect3D9_CreateDevice,                               \
                           reinterpret_cast<void*>(HookedCreateDevice),                      \
                           reinterpret_cast<void**>(&g_origCreateDevice))) {                 \
                OD_LOG("[D3D9] IDirect3D9::CreateDevice hooked (slot %d, orig=%p)",          \
                       N, g_origCreateDevice);                                               \
            }                                                                                \
        }                                                                                    \
        return d3d;                                                                          \
    }
DEFINE_HOOKED_SLOT(0)
DEFINE_HOOKED_SLOT(1)
DEFINE_HOOKED_SLOT(2)
DEFINE_HOOKED_SLOT(3)
#undef DEFINE_HOOKED_SLOT

LPVOID g_slotHookFns[kMaxD3d9Modules] = {
    reinterpret_cast<LPVOID>(HookedDirect3DCreate9_Slot0),
    reinterpret_cast<LPVOID>(HookedDirect3DCreate9_Slot1),
    reinterpret_cast<LPVOID>(HookedDirect3DCreate9_Slot2),
    reinterpret_cast<LPVOID>(HookedDirect3DCreate9_Slot3),
};

bool IsD3d9Module(const char* basename) {
    return _stricmp(basename, "d3d9.dll") == 0;
}

void EnumerateD3d9Modules() {
    HMODULE mods[1024] = {};
    DWORD needed = 0;
    HANDLE proc = GetCurrentProcess();
    if (!EnumProcessModules(proc, mods, sizeof(mods), &needed)) {
        OD_LOG("[D3D9] EnumProcessModules failed: %lu", GetLastError());
        return;
    }
    const int n = (int)(needed / sizeof(HMODULE));
    int found = 0;
    for (int i = 0; i < n && g_d3d9SlotCount < kMaxD3d9Modules; ++i) {
        char path[MAX_PATH] = {};
        if (!GetModuleFileNameExA(proc, mods[i], path, MAX_PATH)) continue;
        const char* slash = strrchr(path, '\\');
        const char* basename = slash ? slash + 1 : path;
        if (!IsD3d9Module(basename)) continue;

        // De-dupe by module handle (in case enumeration returns dupes).
        bool dup = false;
        for (int j = 0; j < g_d3d9SlotCount; ++j) {
            if (g_d3d9Slots[j].module == mods[i]) { dup = true; break; }
        }
        if (dup) continue;

        D3D9HookSlot& slot = g_d3d9Slots[g_d3d9SlotCount];
        slot.module = mods[i];
        strncpy_s(slot.path, path, _TRUNCATE);
        OD_LOG("[D3D9] discovered d3d9 module slot[%d]: %s (base=%p)",
               g_d3d9SlotCount, path, mods[i]);
        ++g_d3d9SlotCount;
        ++found;
    }
    OD_LOG("[D3D9] EnumerateD3d9Modules: %d d3d9 module(s) loaded at install time", found);
}

}  // namespace

bool Install() {
    if (MH_Initialize() != MH_OK) {
        OD_LOG("[D3D9] Install: MH_Initialize failed");
        return false;
    }

    // Build stamp — verify the right binary is loaded. Bumped on every change
    // to D3D9Hook so we can tell from the log whether the user picked up the
    // latest DLL after a rebuild.
    OD_LOG("[D3D9] Build: 2026-05-05-c1aef14+intro (multi-module hook + "
           "periodic rescan + ENB-wrapper introspection for real-device "
           "vtable hooking).");

    EnumerateD3d9Modules();

    // If no d3d9 modules are loaded yet, fall back to the original
    // module-name lookup which will resolve once d3d9 is loaded by
    // delay-load on Skyrim's first Direct3DCreate9 call.
    int hooked = 0;
    if (g_d3d9SlotCount == 0) {
        OD_LOG("[D3D9] No d3d9 modules loaded yet; falling back to module-name resolution");
        LPVOID target = nullptr;
        MH_STATUS s = MH_CreateHookApiEx(
            L"d3d9", "Direct3DCreate9",
            reinterpret_cast<LPVOID>(HookedDirect3DCreate9_Slot0),
            reinterpret_cast<LPVOID*>(&g_d3d9Slots[0].origTramp),
            &target);
        if (s == MH_OK) {
            g_d3d9Slots[0].target = target;
            g_d3d9SlotCount = 1;
            if (MH_EnableHook(target) == MH_OK) {
                ++hooked;
                OD_LOG("[D3D9] Fallback hook installed (slot 0, target=%p)", target);
            }
        } else {
            OD_LOG("[D3D9] Fallback MH_CreateHookApiEx failed: %s",
                   MH_StatusToString(s));
            return false;
        }
    } else {
        // Hook each enumerated module's Direct3DCreate9 export.
        for (int i = 0; i < g_d3d9SlotCount; ++i) {
            FARPROC ep = GetProcAddress(g_d3d9Slots[i].module, "Direct3DCreate9");
            if (!ep) {
                OD_LOG("[D3D9] slot[%d] %s has no Direct3DCreate9 export — skipping",
                       i, g_d3d9Slots[i].path);
                continue;
            }
            MH_STATUS s = MH_CreateHook(reinterpret_cast<LPVOID>(ep),
                                        g_slotHookFns[i],
                                        reinterpret_cast<LPVOID*>(&g_d3d9Slots[i].origTramp));
            if (s != MH_OK) {
                OD_LOG("[D3D9] slot[%d] %s MH_CreateHook failed: %s",
                       i, g_d3d9Slots[i].path, MH_StatusToString(s));
                continue;
            }
            g_d3d9Slots[i].target = reinterpret_cast<LPVOID>(ep);
            if (MH_EnableHook(reinterpret_cast<LPVOID>(ep)) != MH_OK) {
                OD_LOG("[D3D9] slot[%d] MH_EnableHook failed", i);
                continue;
            }
            ++hooked;
            OD_LOG("[D3D9] slot[%d] %s hooked at %p (orig tramp=%p)",
                   i, g_d3d9Slots[i].path, ep, g_d3d9Slots[i].origTramp);
        }
    }

    // Keep the legacy single-export name for existing callers in this
    // file (g_origDirect3DCreate9 is referenced for stats/printf only;
    // not used as a function pointer anymore — slot trampolines are).
    g_origDirect3DCreate9 = g_d3d9Slots[0].origTramp;

    OD_LOG("[D3D9] Install OK: %d/%d d3d9 module(s) hooked at install time. "
           "ENB lazily loads real system32 d3d9 LATER, so call "
           "RescanAndHookNewD3d9Modules() periodically from the worker "
           "thread to pick that up when it appears.",
           hooked, g_d3d9SlotCount);
    return hooked > 0;
}

int RescanAndHookNewD3d9Modules() {
    HMODULE mods[1024] = {};
    DWORD needed = 0;
    HANDLE proc = GetCurrentProcess();
    if (!EnumProcessModules(proc, mods, sizeof(mods), &needed)) return 0;
    const int n = (int)(needed / sizeof(HMODULE));
    int newlyHooked = 0;

    for (int i = 0; i < n && g_d3d9SlotCount < kMaxD3d9Modules; ++i) {
        char path[MAX_PATH] = {};
        if (!GetModuleFileNameExA(proc, mods[i], path, MAX_PATH)) continue;
        const char* slash = strrchr(path, '\\');
        const char* basename = slash ? slash + 1 : path;
        if (!IsD3d9Module(basename)) continue;

        // Already in our slot table?
        bool already = false;
        for (int j = 0; j < g_d3d9SlotCount; ++j) {
            if (g_d3d9Slots[j].module == mods[i]) { already = true; break; }
        }
        if (already) continue;

        const int slotIdx = g_d3d9SlotCount;
        D3D9HookSlot& slot = g_d3d9Slots[slotIdx];
        slot.module = mods[i];
        strncpy_s(slot.path, path, _TRUNCATE);

        FARPROC ep = GetProcAddress(slot.module, "Direct3DCreate9");
        if (!ep) {
            OD_LOG("[D3D9] rescan: slot[%d] %s has no Direct3DCreate9 export — skipping",
                   slotIdx, path);
            ++g_d3d9SlotCount;  // record the slot so we don't re-process the same module
            continue;
        }
        MH_STATUS s = MH_CreateHook(reinterpret_cast<LPVOID>(ep),
                                    g_slotHookFns[slotIdx],
                                    reinterpret_cast<LPVOID*>(&slot.origTramp));
        if (s != MH_OK) {
            OD_LOG("[D3D9] rescan: slot[%d] %s MH_CreateHook failed: %s",
                   slotIdx, path, MH_StatusToString(s));
            ++g_d3d9SlotCount;
            continue;
        }
        slot.target = reinterpret_cast<LPVOID>(ep);
        if (MH_EnableHook(reinterpret_cast<LPVOID>(ep)) != MH_OK) {
            OD_LOG("[D3D9] rescan: slot[%d] MH_EnableHook failed", slotIdx);
            ++g_d3d9SlotCount;
            continue;
        }
        ++g_d3d9SlotCount;
        ++newlyHooked;
        OD_LOG("[D3D9] rescan: NEW slot[%d] %s hooked at %p (orig tramp=%p) — "
               "this is likely real-d3d9 that ENB lazy-loaded after our "
               "DllMain enumerated. ENB's calls on the real device will "
               "now funnel through our hook chain.",
               slotIdx, path, ep, slot.origTramp);
    }
    return newlyHooked;
}

// =============================================================================
// ENB-bypass fix: probe ENB's wrapped device for the embedded real
// IDirect3DDevice9 pointer and hook its vtable directly.
// =============================================================================
// First test (commit 113fac8) confirmed ENB still bypasses: pipeline mode
// caused triangle glitches with the multi-module hook in place. Conclusion:
// ENB stores a saved pointer to the real device that was created BEFORE
// our slot[1] hook landed (we hooked real-d3d9!Direct3DCreate9 at +1.7s
// from DllMain via periodic rescan, but ENB had already called it at
// +1.1s). The real device's vtable was not modified at construction time,
// so ENB's internal Get/Set calls on that saved pointer don't hit Mirror.
//
// Heuristic: walk the wrapped device's first 64 bytes (16 dwords). For
// each dword that points to readable committed memory whose first dword
// (vtable pointer) lies inside a known d3d9.dll module's image AND whose
// vtable[0] (QueryInterface) is also inside that module's executable
// section — that's a real D3D9 IDirect3DDevice9. Apply the same bulk-hook
// + Mirror::Install we apply to the wrapper.
//
// Static for internal linkage; visible from the upper anonymous namespace
// via implicit using-directive of the lower anon ns (where g_d3d9Slots
// lives) and explicit forward decl at the top of the file.

namespace {

bool InModule(void* addr, HMODULE mod) {
    if (!mod) return false;
    MODULEINFO mi = {};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) return false;
    const uintptr_t lo = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
    const uintptr_t hi = lo + mi.SizeOfImage;
    const uintptr_t a  = reinterpret_cast<uintptr_t>(addr);
    return a >= lo && a < hi;
}

bool IsLikelyD3D9DevicePointer(void* candidate) {
    if (!candidate) return false;

    MEMORY_BASIC_INFORMATION mbi = {};
    if (!VirtualQuery(candidate, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    constexpr DWORD kReadable =
        PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
    if (!(mbi.Protect & kReadable)) return false;
    if (mbi.Protect & PAGE_GUARD)   return false;

    void* vt = *reinterpret_cast<void**>(candidate);
    if (!vt) return false;

    bool vtInD3d9 = false;
    for (int i = 0; i < g_d3d9SlotCount; ++i) {
        if (InModule(vt, g_d3d9Slots[i].module)) { vtInD3d9 = true; break; }
    }
    if (!vtInD3d9) return false;

    if (!VirtualQuery(vt, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT || !(mbi.Protect & kReadable)) return false;
    void* fn0 = *reinterpret_cast<void**>(vt);
    if (!fn0) return false;

    for (int i = 0; i < g_d3d9SlotCount; ++i) {
        if (InModule(fn0, g_d3d9Slots[i].module)) return true;
    }
    return false;
}

constexpr int kMaxRealDevices = 4;
IDirect3DDevice9* g_hookedRealDevices[kMaxRealDevices] = {};
int               g_hookedRealDeviceCount = 0;

void HookRealDeviceVtable(IDirect3DDevice9* realDev) {
    if (!realDev) return;
    for (int i = 0; i < g_hookedRealDeviceCount; ++i) {
        if (g_hookedRealDevices[i] == realDev) return;  // already hooked
    }
    if (g_hookedRealDeviceCount >= kMaxRealDevices) {
        OD_LOG("[D3D9] real-device hook table full (%d) — skipping", kMaxRealDevices);
        return;
    }
    g_hookedRealDevices[g_hookedRealDeviceCount++] = realDev;

    OD_LOG("[D3D9] HookRealDeviceVtable: applying bulk-hook + Mirror::Install "
           "to real IDirect3DDevice9 %p (vtable=%p)",
           realDev, *reinterpret_cast<void**>(realDev));

    d3d9vt::BulkHookDevice(realDev);
    mirror::Install(realDev);
    // Don't re-hook Present on the real device — Skyrim only calls Present
    // through the wrapper, and ENB's present-time effects loop through its
    // own present chain (not by calling our HookedPresent on the real device).
}

}  // namespace

static void TryHookEmbeddedRealDevice(IDirect3DDevice9* wrapped) {
    if (!wrapped) return;
    if (g_d3d9SlotCount < 2) {
        OD_LOG("[D3D9] TryHookEmbeddedRealDevice: skipping — only %d d3d9 "
               "module(s) known. Real d3d9 hasn't been discovered yet.",
               g_d3d9SlotCount);
        return;
    }

    const uint8_t* wbytes = reinterpret_cast<const uint8_t*>(wrapped);
    int found = 0;
    for (int off = sizeof(void*); off <= 0x40; off += sizeof(void*)) {
        MEMORY_BASIC_INFORMATION wmbi = {};
        if (!VirtualQuery(wbytes + off, &wmbi, sizeof(wmbi))) break;
        if (wmbi.State != MEM_COMMIT) break;

        void* candidate = *reinterpret_cast<void* const*>(wbytes + off);
        if (candidate == wrapped) continue;
        if (!IsLikelyD3D9DevicePointer(candidate)) continue;

        OD_LOG("[D3D9] TryHookEmbeddedRealDevice: candidate at wrapper offset "
               "0x%02X is %p, vtable=%p — looks like a real D3D9 device. "
               "Hooking its vtable.",
               off, candidate, *reinterpret_cast<void* const*>(candidate));

        HookRealDeviceVtable(reinterpret_cast<IDirect3DDevice9*>(candidate));
        ++found;
    }
    if (found == 0) {
        OD_LOG("[D3D9] TryHookEmbeddedRealDevice: no plausible real-device "
               "pointer found in wrapper %p first 0x40 bytes. ENB may store "
               "the real device deeper in the wrapper struct, or at a "
               "different offset than expected.",
               wrapped);
    } else {
        OD_LOG("[D3D9] TryHookEmbeddedRealDevice: hooked %d real-device "
               "candidate(s). ENB's internal direct reads should now land "
               "on Mirror's shadow.", found);
    }
}

}  // namespace overdrive::d3d9hook
