#include "D3D9Hook.h"
#include "DebugLogger.h"
#include "MinHook/MinHook.h"
#include "D3D9DeviceVtable.h"
#include "D3D9Mirror.h"
#include "D3D9PipelineDispatcher.h"

#include <windows.h>
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

bool Install() {
    if (MH_Initialize() != MH_OK) {
        OD_LOG("[D3D9] Install: MH_Initialize failed");
        return false;
    }

    LPVOID target = nullptr;
    MH_STATUS s = MH_CreateHookApiEx(
        L"d3d9", "Direct3DCreate9",
        reinterpret_cast<LPVOID>(HookedDirect3DCreate9),
        reinterpret_cast<LPVOID*>(&g_origDirect3DCreate9),
        &target);
    if (s != MH_OK) {
        OD_LOG("[D3D9] Install: MH_CreateHookApiEx(d3d9!Direct3DCreate9) failed: %s",
               MH_StatusToString(s));
        return false;
    }
    OD_LOG("[D3D9] Created hook on d3d9!Direct3DCreate9 (target=%p, orig trampoline=%p)",
           target, g_origDirect3DCreate9);

    s = MH_EnableHook(target);
    if (s != MH_OK) {
        OD_LOG("[D3D9] Install: MH_EnableHook failed: %s", MH_StatusToString(s));
        return false;
    }
    OD_LOG("[D3D9] Install OK: Direct3DCreate9 inline-hooked.");
    return true;
}

}  // namespace overdrive::d3d9hook
