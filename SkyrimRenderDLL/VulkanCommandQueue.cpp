#include "VulkanCommandQueue.h"
#include "DebugLogger.h"
#include "Globals.h"
#include "DxbcToSpirv.h"
#include "DxbcParser.h"
#include "ResourceMirror.h"

// volk is vendored at the SkyrimRenderDLL root from the SDL3+Vulkan window
// experiment. It dynamically loads vulkan-1.dll without a static .lib so
// the DLL works on systems without the Vulkan SDK installed at link time.
#define VK_USE_PLATFORM_WIN32_KHR
#include "volk.h"

#include <windows.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>

namespace overdrive::vkq {

namespace {

// =============================================================================
// Phase B — multi-producer queue (the actual multi-core enabler)
// =============================================================================
//
// Single-producer single-consumer was fine while every push came from one
// thread (Skyrim funnels everything through the D3D9 device-lock today, so
// only one thread is in our wrappers at a time). The whole *reason* to
// replace D3D9 with our own path is to let Skyrim's worker threads record
// draws concurrently. Once that happens, a single shared ring would re-
// introduce the exact lock contention we're trying to eliminate.
//
// Each producer thread claims its own SPSC ring on first Push. Subsequent
// pushes from that thread go to the local ring with zero atomics other
// than the head store — same cost as the old single-ring path. Multiple
// producers never touch each other's ring (different cache lines via
// alignas(64)), so there is no false sharing and no contention.
//
// The drain thread fans in: it round-robins over all registered slots,
// pulling up to N cmds from each per pass. The order of cmds within a
// single producer is preserved (in-order on that producer's ring); cross-
// producer order is interleaved by the drain. For state-mutating cmds
// from a single producer, that's exactly what we need.
//
// Sizing: 8 slots × 8K entries × 20 bytes = 1.28 MB total. Skyrim has ~6
// active worker threads + 1 main render thread; 8 slots is comfortable.
// 8K per slot absorbs ~1 full frame's worth of state changes per producer
// at peak rate — plenty for a non-realtime drain.

struct alignas(64) ProducerRing {
    // 32K entries × 20 bytes = 640 KB per slot, 5 MB total across 8 slots.
    // The previous 8K size was overflowing under burst loads — when a slot's
    // drain thread also handles frame-boundary work (BEGIN_SCENE → vkWait
    // ForFences ~5ms, END_SCENE → SubmitVkFrame spin-wait), the producer
    // can push 100k+ cmds in the meantime. Observed in real log: dropped=
    // 41865 with depth=7140/8192. 4x ring depth absorbs that burst.
    static constexpr uint32_t kSize = 32768;
    static constexpr uint32_t kMask = kSize - 1;

    Cmd ring[kSize];
    // SPSC head/tail per Lamport — head touched by producer, tail by drain.
    // alignas(64) on the struct keeps each ring on its own cache line set;
    // explicit padding around head/tail isn't required because the whole
    // struct is the unit of producer ownership.
    std::atomic<uint32_t> head{0};
    std::atomic<uint32_t> tail{0};
    // Slot ownership: tid of the registering producer, 0 = free.
    std::atomic<uint32_t> ownerTid{0};
    // Per-producer stats. 32-bit on x86: every Push fires `pushed.fetch_add`,
    // ~135k/s on the render thread. uint64 atomic fetch_add = LOCK CMPXCHG8B
    // (~50 cyc); uint32 = LOCK XADD (~10 cyc). Per-second deltas wrap-safe.
    std::atomic<uint32_t> pushed{0};
    std::atomic<uint32_t> popped{0};
    // Phase B.2 — per-slot drain thread. Spawned lazily when the slot is
    // claimed. Drains ONLY this slot's ring → real CPU parallelism across
    // producers (each pair of producer + drain runs on its own pair of CPUs
    // with zero contention). Slot 0 is special: its drain thread does the
    // Vulkan render-pass work (BEGIN_SCENE / END_SCENE / draws) because
    // those cmds always come from the render thread, which always claims
    // slot 0 first. Other slots' drains just count + bookkeep.
    HANDLE drainThread = nullptr;
    DWORD  drainThreadId = 0;
    // Per-slot opcode histogram, updated by the slot's drain thread only.
    uint64_t opCount[CMD_COUNT_] = {};
};

constexpr uint32_t kMaxProducers = 8;
ProducerRing g_producers[kMaxProducers];
// High-water mark of registered slots — drain only iterates [0, hwm). No
// slot ever decrements this (slots are sticky on release for cheap reuse).
std::atomic<uint32_t> g_producerHWM{0};

// Per-thread slot index. -1 = unregistered. First Push claims a slot.
thread_local int tl_producerSlot = -1;

// 32-bit on x86: hot-path atomics on the render thread. See ProducerRing
// comment above for the LOCK CMPXCHG8B vs LOCK XADD rationale.
std::atomic<uint32_t> g_pushed{0};
std::atomic<uint32_t> g_popped{0};
std::atomic<uint32_t> g_dropped{0};   // queue-full drops

std::atomic<bool> g_stopRequested{false};

// =============================================================================
// Vulkan boot — Phase A.1: instance + device + graphics queue + command pool
// =============================================================================
// Validates the Vulkan side is workable before we wire any actual command
// translation. After Install completes, we should have:
//   - A valid VkInstance
//   - A picked VkPhysicalDevice (preferring discrete GPU)
//   - A VkDevice with one graphics-capable queue
//   - A VkCommandPool we can reset/allocate command buffers from
//
// We do NOT create a swapchain or surface yet. That comes later (when we're
// ready to actually display Vulkan output instead of the D3D9 backbuffer).
// All current submissions are headless / off-screen.

VkInstance       g_vkInstance        = VK_NULL_HANDLE;
VkPhysicalDevice g_vkPhysicalDevice  = VK_NULL_HANDLE;
VkDevice         g_vkDevice          = VK_NULL_HANDLE;
VkQueue          g_vkGfxQueue        = VK_NULL_HANDLE;
uint32_t         g_vkGfxQueueFamily  = 0;
VkCommandPool    g_vkCmdPool         = VK_NULL_HANDLE;
bool             g_vkReady           = false;
char             g_vkDeviceName[256] = {};

// =============================================================================
// Phase A.3b — VkPipelineCache (persistent across game sessions)
// =============================================================================
// Pipeline creation in Vulkan is expensive — minutes of accumulated shader
// compile time over a play session. The pipeline cache lets the driver reuse
// already-compiled pipeline state. We persist it to disk so subsequent launches
// start with a warm cache instead of recompiling the same pipelines.
//
// Layout on disk (skyrim_overdrive_pipeline.cache):
//   The raw blob produced by vkGetPipelineCacheData. The driver embeds its own
//   header (UUID, vendor ID, device ID) and validates them on load — so the
//   blob is automatically rejected if the user swaps GPUs or updates drivers.
//   No need for our own versioning.
//
// Phase A.3c+ pipelines (one per VS+PS+VertexFormat tuple) will be created
// with this cache. For now the cache exists but no pipelines reference it yet.
VkPipelineCache  g_vkPipelineCache  = VK_NULL_HANDLE;
size_t           g_vkPipelineCacheLoadedBytes = 0;

// Phase A.2: pre-allocated ring of command buffers + fences. Each "frame" of
// drained commands is recorded into one cb, submitted to the queue, and the
// fence tracks completion. The drain thread cycles through 4 cbs so we don't
// have to wait for GPU completion before starting the next frame's record.
constexpr int kVkFrameRing = 4;
VkCommandBuffer  g_vkCmdBuffers[kVkFrameRing] = {};
VkFence          g_vkFences[kVkFrameRing]     = {};
int              g_vkFrameIdx                  = 0;
uint64_t         g_vkSubmits                   = 0;   // total submits
uint64_t         g_vkLastSubmits               = 0;
uint64_t         g_vkCmdsThisFrame             = 0;
uint64_t         g_vkLastSubmitMicros          = 0;

// =============================================================================
// Phase B.2.1 — per-slot Vulkan command pools + secondary command buffers
// =============================================================================
//
// Each producer slot gets its own VkCommandPool + 4-deep secondary CB ring.
// This is the Vulkan-side foundation for parallel command recording:
//   - Vulkan command pools are NOT thread-safe (one thread at a time per pool).
//     Per-slot pools = each per-slot drain thread owns its pool exclusively.
//   - Secondary command buffers can be recorded in parallel and stitched into
//     a primary CB later via vkCmdExecuteCommands. That's the multi-core win.
//
// This phase only ALLOCATES the infrastructure. The actual cross-thread
// recording protocol (each drain records into its own secondary; slot[0]
// stitches them at frame boundaries) lands next turn alongside the frame-
// epoch synchronization. Splitting it this way keeps the diff reviewable
// and validates pool/CB allocation works on the AMD driver before we
// pile on the synchronization layer.
struct alignas(64) SlotVulkan {
    VkCommandPool   pool = VK_NULL_HANDLE;
    VkCommandBuffer secondary[kVkFrameRing] = {};
    // Index of the secondary CB currently being recorded by this slot's
    // drain thread. Increments modulo kVkFrameRing on each frame boundary.
    int             curIdx = 0;
    // Whether vkBeginCommandBuffer has been called on secondary[curIdx]
    // and we're mid-recording. Reset on frame boundary.
    bool            recording = false;
    // Cross-thread frame coordination — slot[0] reads these to know when
    // a slot has a complete secondary ready for stitching. Wired up in
    // the next turn; allocated here so the layout is final.
    std::atomic<uint64_t> activeEpoch{0};
    std::atomic<uint64_t> publishedEpoch{0};
    VkCommandBuffer       publishedCb = VK_NULL_HANDLE;
};
SlotVulkan g_slotVulkan[kMaxProducers];

// Frame-epoch counter — bumped by slot[0] on each BEGIN_SCENE. Wired up
// in the next turn (B.2.2). Defined here so per-slot drain threads can
// already read it (currently a no-op since publishedEpoch isn't yet set).
std::atomic<uint64_t> g_frameEpoch{0};

// =============================================================================
// Live shader translator — D3D9 shader create -> SPIR-V -> VkShaderModule
// =============================================================================
//
// Wired into ResourceMirror's Note{Vertex,Pixel}Shader callback so every
// shader Skyrim creates immediately gets translated and a VkShaderModule
// gets cached. Translator pass-rate becomes a real-time signal: every 5s
// the periodic log prints "[LiveXlat] vs=ok/total ps=ok/total". When the
// real translator opcode coverage is high enough, those numbers approach
// 100% and we know the Vulkan-side pipeline path is unblocked for the
// VkPipeline factory + draw recording stage.
//
// Thread safety: NoteVertex/PixelShader can fire from any thread (often
// the main thread or a worker that creates resources). vkCreateShaderModule
// is documented as externally synchronized at the device level — we wrap
// the calls in a single mutex. Cost is negligible since shader creation
// is rare (~1100 shaders total per Skyrim session).
struct LiveXlat {
    std::mutex                                     mtx;
    std::unordered_map<const void*, VkShaderModule> vsModules;
    std::unordered_map<const void*, VkShaderModule> psModules;
    std::atomic<uint32_t> vsTried{0}, vsOk{0};
    std::atomic<uint32_t> psTried{0}, psOk{0};
    uint32_t lastLogVsOk = 0, lastLogPsOk = 0;
    // Bucket of fail reasons from REAL translation attempts (not passthrough).
    // Tells us which opcode/feature is gating remaining shaders. Mutex-
    // protected because shader creation can come from any thread.
    std::unordered_map<std::string, uint32_t> failBuckets;
};
LiveXlat g_xlat;

void LiveTranslateShaderCb(const void* d3d9Ptr,
                           const uint32_t* bytecode, size_t dwords,
                           bool isPixelShader) {
    if (!g_vkReady || !bytecode || dwords < 2) return;
    if (isPixelShader) g_xlat.psTried.fetch_add(1, std::memory_order_relaxed);
    else               g_xlat.vsTried.fetch_add(1, std::memory_order_relaxed);

    // Decode + translate. Both are pure CPU work, no Vulkan calls — runs
    // outside the mutex.
    overdrive::dxbc::Decoded dec = overdrive::dxbc::Decode(bytecode, dwords);
    if (!dec.ok) return;
    // Snapshot real-count BEFORE translation, then check after to detect
    // whether this specific shader hit the real translator path or fell
    // back to passthrough. If real-count didn't advance, bucket the fail
    // reason so the periodic log surfaces what's gating coverage.
    uint32_t realBefore = overdrive::dxbc_spirv::TranslatedRealCount();
    std::vector<uint32_t> spirv = overdrive::dxbc_spirv::Translate(dec);
    if (spirv.empty()) return;
    uint32_t realAfter = overdrive::dxbc_spirv::TranslatedRealCount();
    if (realAfter == realBefore && !dec.isPixelShader) {
        // VS fell back to passthrough — capture the reason from the
        // translator's last-fail buffer.
        const char* why = overdrive::dxbc_spirv::LastFailReason();
        if (why && why[0]) {
            std::lock_guard<std::mutex> lk(g_xlat.mtx);
            g_xlat.failBuckets[why]++;
        }
    }

    // vkCreateShaderModule requires external sync at the device. Skyrim
    // creates ~1100 shaders total in a session; this mutex is uncontended
    // 99.9% of the time.
    VkShaderModuleCreateInfo smi = {};
    smi.sType    = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    smi.codeSize = spirv.size() * sizeof(uint32_t);
    smi.pCode    = spirv.data();

    VkShaderModule mod = VK_NULL_HANDLE;
    {
        std::lock_guard<std::mutex> lk(g_xlat.mtx);
        VkResult r = vkCreateShaderModule(g_vkDevice, &smi, nullptr, &mod);
        if (r != VK_SUCCESS) return;
        if (isPixelShader) g_xlat.psModules[d3d9Ptr] = mod;
        else               g_xlat.vsModules[d3d9Ptr] = mod;
    }
    if (isPixelShader) g_xlat.psOk.fetch_add(1, std::memory_order_relaxed);
    else               g_xlat.vsOk.fetch_add(1, std::memory_order_relaxed);
}

void DestroyLiveTranslatedModules() {
    if (!g_vkDevice) return;
    std::lock_guard<std::mutex> lk(g_xlat.mtx);
    for (auto& kv : g_xlat.vsModules) {
        if (kv.second) vkDestroyShaderModule(g_vkDevice, kv.second, nullptr);
    }
    for (auto& kv : g_xlat.psModules) {
        if (kv.second) vkDestroyShaderModule(g_vkDevice, kv.second, nullptr);
    }
    g_xlat.vsModules.clear();
    g_xlat.psModules.clear();
}

// =============================================================================
// Phase A.3a — off-screen color render target
// =============================================================================
// One persistent VkImage we render into each frame. Single subpass, single
// attachment, BGRA8 to match D3D9 backbuffer format. 1280x720 — small enough
// to allocate trivially, large enough that future translation of real D3D9
// draws will produce visible output once we composite.
//
// Per-frame work in the drain thread:
//   BeginVkFrame:
//     vkBeginCommandBuffer
//     vkCmdBeginRenderPass (CLEAR_OP_CLEAR with color [0.05, 0.10, 0.20, 1.0])
//   per draw cmd:
//     vkCmdPipelineBarrier (placeholder — real vkCmdDraw lands in A.3g)
//   SubmitVkFrame:
//     vkCmdEndRenderPass
//     vkEndCommandBuffer
//     vkQueueSubmit(fence)
//
// Skyrim's actual rendering is unaffected — D3D9 still owns the on-screen
// backbuffer. Our Vulkan output is invisible until A.4 composites it.
constexpr uint32_t kRtWidth   = 1280;
constexpr uint32_t kRtHeight  = 720;
constexpr VkFormat kRtFormat  = VK_FORMAT_B8G8R8A8_UNORM;

VkImage         g_rtImage      = VK_NULL_HANDLE;
VkDeviceMemory  g_rtImageMem   = VK_NULL_HANDLE;
VkImageView     g_rtImageView  = VK_NULL_HANDLE;
VkRenderPass    g_rtRenderPass = VK_NULL_HANDLE;
VkFramebuffer   g_rtFramebuf   = VK_NULL_HANDLE;

std::string PipelineCachePath() {
    if (gSkyrimDir.empty()) return std::string();
    return gSkyrimDir + "\\skyrim_overdrive_pipeline.cache";
}

bool LoadPipelineCache() {
    std::vector<uint8_t> blob;
    std::string path = PipelineCachePath();
    if (!path.empty()) {
        HANDLE f = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz; GetFileSizeEx(f, &sz);
            // Sanity cap — a real cache rarely exceeds a few MB. Reject anything
            // beyond 64 MB as corrupt or malicious.
            if (sz.QuadPart > 0 && sz.QuadPart < 64 * 1024 * 1024) {
                blob.resize((size_t)sz.QuadPart);
                DWORD got = 0;
                ReadFile(f, blob.data(), (DWORD)blob.size(), &got, nullptr);
                if (got != blob.size()) blob.clear();
            }
            CloseHandle(f);
        }
    }

    VkPipelineCacheCreateInfo pci = {};
    pci.sType           = VK_STRUCTURE_TYPE_PIPELINE_CACHE_CREATE_INFO;
    pci.initialDataSize = blob.size();
    pci.pInitialData    = blob.empty() ? nullptr : blob.data();
    if (vkCreatePipelineCache(g_vkDevice, &pci, nullptr, &g_vkPipelineCache) != VK_SUCCESS) {
        // Driver rejected the blob (UUID mismatch etc.) — retry empty.
        if (!blob.empty()) {
            OD_LOG("[VkQ] Pipeline cache blob rejected by driver (likely "
                   "GPU/driver change since last run). Starting empty.");
            VkPipelineCacheCreateInfo empty = {};
            empty.sType = VK_STRUCTURE_TYPE_PIPELINE_CACHE_CREATE_INFO;
            if (vkCreatePipelineCache(g_vkDevice, &empty, nullptr, &g_vkPipelineCache) != VK_SUCCESS) {
                OD_LOG("[VkQ] vkCreatePipelineCache(empty) also failed");
                return false;
            }
        } else {
            OD_LOG("[VkQ] vkCreatePipelineCache failed");
            return false;
        }
    }
    g_vkPipelineCacheLoadedBytes = blob.size();
    OD_LOG("[VkQ] Phase A.3b pipeline cache READY: loaded %zu bytes from '%s'%s",
           g_vkPipelineCacheLoadedBytes,
           path.empty() ? "(no path)" : path.c_str(),
           blob.empty() ? " (cold start, will populate this session)" : " (warm)");
    return true;
}

void SavePipelineCache() {
    if (!g_vkPipelineCache || !g_vkDevice) return;
    std::string path = PipelineCachePath();
    if (path.empty()) return;

    size_t sz = 0;
    if (vkGetPipelineCacheData(g_vkDevice, g_vkPipelineCache, &sz, nullptr) != VK_SUCCESS) return;
    if (sz == 0) {
        OD_LOG("[VkQ] pipeline cache empty at shutdown — nothing to save");
        return;
    }
    std::vector<uint8_t> blob(sz);
    if (vkGetPipelineCacheData(g_vkDevice, g_vkPipelineCache, &sz, blob.data()) != VK_SUCCESS) return;
    blob.resize(sz);

    // Skip write if the cache hasn't grown since load — avoids touching the
    // file on cold-start sessions where no pipelines were created yet.
    if (sz == g_vkPipelineCacheLoadedBytes) {
        OD_LOG("[VkQ] pipeline cache unchanged (%zu bytes) — skipping write", sz);
        return;
    }

    HANDLE f = CreateFileA(path.c_str(), GENERIC_WRITE, 0,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        OD_LOG("[VkQ] could not open '%s' for write: %lu", path.c_str(), GetLastError());
        return;
    }
    DWORD wrote = 0;
    WriteFile(f, blob.data(), (DWORD)blob.size(), &wrote, nullptr);
    CloseHandle(f);
    OD_LOG("[VkQ] pipeline cache saved: %zu bytes -> '%s' (was %zu at load)",
           sz, path.c_str(), g_vkPipelineCacheLoadedBytes);
}

uint32_t FindMemoryType(uint32_t typeBits, VkMemoryPropertyFlags want) {
    VkPhysicalDeviceMemoryProperties mp;
    vkGetPhysicalDeviceMemoryProperties(g_vkPhysicalDevice, &mp);
    for (uint32_t i = 0; i < mp.memoryTypeCount; ++i) {
        if ((typeBits & (1u << i)) &&
            (mp.memoryTypes[i].propertyFlags & want) == want) {
            return i;
        }
    }
    return UINT32_MAX;
}

bool CreateOffscreenTarget() {
    // 1. The color image itself.
    VkImageCreateInfo ic = {};
    ic.sType         = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    ic.imageType     = VK_IMAGE_TYPE_2D;
    ic.format        = kRtFormat;
    ic.extent        = { kRtWidth, kRtHeight, 1 };
    ic.mipLevels     = 1;
    ic.arrayLayers   = 1;
    ic.samples       = VK_SAMPLE_COUNT_1_BIT;
    ic.tiling        = VK_IMAGE_TILING_OPTIMAL;
    ic.usage         = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT |
                       VK_IMAGE_USAGE_SAMPLED_BIT;   // sampled = future composite
    ic.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    if (vkCreateImage(g_vkDevice, &ic, nullptr, &g_rtImage) != VK_SUCCESS) {
        OD_LOG("[VkQ] vkCreateImage(offscreen) failed");
        return false;
    }

    // 2. Allocate device-local memory for it.
    VkMemoryRequirements mr;
    vkGetImageMemoryRequirements(g_vkDevice, g_rtImage, &mr);
    VkMemoryAllocateInfo mai = {};
    mai.sType           = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    mai.allocationSize  = mr.size;
    mai.memoryTypeIndex = FindMemoryType(mr.memoryTypeBits,
                                         VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if (mai.memoryTypeIndex == UINT32_MAX) {
        OD_LOG("[VkQ] no DEVICE_LOCAL memory type for offscreen image");
        return false;
    }
    if (vkAllocateMemory(g_vkDevice, &mai, nullptr, &g_rtImageMem) != VK_SUCCESS) {
        OD_LOG("[VkQ] vkAllocateMemory(%llu bytes) failed", (unsigned long long)mr.size);
        return false;
    }
    vkBindImageMemory(g_vkDevice, g_rtImage, g_rtImageMem, 0);

    // 3. Image view for the color attachment.
    VkImageViewCreateInfo vci = {};
    vci.sType    = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    vci.image    = g_rtImage;
    vci.viewType = VK_IMAGE_VIEW_TYPE_2D;
    vci.format   = kRtFormat;
    vci.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    vci.subresourceRange.levelCount = 1;
    vci.subresourceRange.layerCount = 1;
    if (vkCreateImageView(g_vkDevice, &vci, nullptr, &g_rtImageView) != VK_SUCCESS) {
        OD_LOG("[VkQ] vkCreateImageView(offscreen) failed");
        return false;
    }

    // 4. Render pass: one subpass, one color attachment, CLEAR→STORE.
    VkAttachmentDescription att = {};
    att.format         = kRtFormat;
    att.samples        = VK_SAMPLE_COUNT_1_BIT;
    att.loadOp         = VK_ATTACHMENT_LOAD_OP_CLEAR;
    att.storeOp        = VK_ATTACHMENT_STORE_OP_STORE;
    att.stencilLoadOp  = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    att.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    att.initialLayout  = VK_IMAGE_LAYOUT_UNDEFINED;
    att.finalLayout    = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;

    VkAttachmentReference attRef = {};
    attRef.attachment = 0;
    attRef.layout     = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;

    VkSubpassDescription sub = {};
    sub.pipelineBindPoint    = VK_PIPELINE_BIND_POINT_GRAPHICS;
    sub.colorAttachmentCount = 1;
    sub.pColorAttachments    = &attRef;

    VkRenderPassCreateInfo rpci = {};
    rpci.sType           = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
    rpci.attachmentCount = 1;
    rpci.pAttachments    = &att;
    rpci.subpassCount    = 1;
    rpci.pSubpasses      = &sub;
    if (vkCreateRenderPass(g_vkDevice, &rpci, nullptr, &g_rtRenderPass) != VK_SUCCESS) {
        OD_LOG("[VkQ] vkCreateRenderPass(offscreen) failed");
        return false;
    }

    // 5. Framebuffer — binds the image view to the render pass attachment 0.
    VkFramebufferCreateInfo fci = {};
    fci.sType           = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
    fci.renderPass      = g_rtRenderPass;
    fci.attachmentCount = 1;
    fci.pAttachments    = &g_rtImageView;
    fci.width           = kRtWidth;
    fci.height          = kRtHeight;
    fci.layers          = 1;
    if (vkCreateFramebuffer(g_vkDevice, &fci, nullptr, &g_rtFramebuf) != VK_SUCCESS) {
        OD_LOG("[VkQ] vkCreateFramebuffer(offscreen) failed");
        return false;
    }

    OD_LOG("[VkQ] Phase A.3a offscreen target READY: %ux%u BGRA8 (%llu bytes), "
           "render pass + framebuffer created",
           kRtWidth, kRtHeight, (unsigned long long)mr.size);
    return true;
}

void DestroyOffscreenTarget() {
    if (g_rtFramebuf)   vkDestroyFramebuffer(g_vkDevice, g_rtFramebuf,  nullptr);
    if (g_rtRenderPass) vkDestroyRenderPass (g_vkDevice, g_rtRenderPass, nullptr);
    if (g_rtImageView)  vkDestroyImageView  (g_vkDevice, g_rtImageView, nullptr);
    if (g_rtImage)      vkDestroyImage      (g_vkDevice, g_rtImage,     nullptr);
    if (g_rtImageMem)   vkFreeMemory        (g_vkDevice, g_rtImageMem,  nullptr);
    g_rtFramebuf = VK_NULL_HANDLE;
    g_rtRenderPass = VK_NULL_HANDLE;
    g_rtImageView = VK_NULL_HANDLE;
    g_rtImage = VK_NULL_HANDLE;
    g_rtImageMem = VK_NULL_HANDLE;
}

// =============================================================================
// Phase B.2.2 — secondary CB lifecycle helpers
// =============================================================================
// Begin / end / publish / roll a slot's secondary CB. Each function is only
// safe to call from the slot's drain thread (the pool's owner). Slot 0 is
// the exception — its drain thread also runs BeginVkFrame and SubmitVkFrame,
// which roll slot[0]'s secondary inline. Same thread, same pool — safe.

bool BeginSecondary(int slotIdx) {
    if (!g_vkReady) return false;
    SlotVulkan& sv = g_slotVulkan[slotIdx];
    if (!sv.pool) return false;
    if (sv.recording) return true;

    VkCommandBufferInheritanceInfo inh = {};
    inh.sType       = VK_STRUCTURE_TYPE_COMMAND_BUFFER_INHERITANCE_INFO;
    inh.renderPass  = g_rtRenderPass;
    inh.subpass     = 0;
    inh.framebuffer = g_rtFramebuf;   // optional but enables tile-based opt

    VkCommandBufferBeginInfo bi = {};
    bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    // RENDER_PASS_CONTINUE_BIT is required for secondaries called via
    // vkCmdExecuteCommands inside a render pass. ONE_TIME_SUBMIT_BIT means
    // the driver can throw away any optimization state after each frame.
    bi.flags = VK_COMMAND_BUFFER_USAGE_RENDER_PASS_CONTINUE_BIT
             | VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    bi.pInheritanceInfo = &inh;

    VkResult r = vkBeginCommandBuffer(sv.secondary[sv.curIdx], &bi);
    if (r != VK_SUCCESS) return false;
    sv.recording = true;
    return true;
}

void EndAndPublishSecondary(int slotIdx) {
    SlotVulkan& sv = g_slotVulkan[slotIdx];
    if (!sv.recording) return;
    vkEndCommandBuffer(sv.secondary[sv.curIdx]);
    sv.publishedCb = sv.secondary[sv.curIdx];
    // Publish epoch AFTER publishedCb is written — readers (slot[0]
    // SubmitVkFrame) use publishedEpoch as the gate, so it must release-
    // store after publishedCb is visible.
    sv.publishedEpoch.store(sv.activeEpoch.load(std::memory_order_relaxed),
                            std::memory_order_release);
    sv.recording = false;
}

// Advance this slot to the new epoch: end the in-flight secondary, publish
// it, advance the ring index, begin a fresh secondary. activeEpoch jumps
// directly to newEpoch so a slot lagging by many epochs catches up in one
// step instead of N rolls.
void RollSecondaryToEpoch(int slotIdx, uint64_t newEpoch) {
    SlotVulkan& sv = g_slotVulkan[slotIdx];
    EndAndPublishSecondary(slotIdx);
    sv.curIdx = (sv.curIdx + 1) % kVkFrameRing;
    sv.activeEpoch.store(newEpoch, std::memory_order_relaxed);
    BeginSecondary(slotIdx);
}

// Record one drained cmd into this slot's current secondary CB. Today we
// only emit vkCmdSetViewport for draw cmds; once the translator lands,
// real vkCmdBindPipeline / vkCmdBindDescriptorSets / vkCmdDrawIndexed go
// through here unchanged. Same call from N threads → N concurrent recorders.
void RecordCmdIntoSecondary(int slotIdx, const Cmd& local) {
    SlotVulkan& sv = g_slotVulkan[slotIdx];
    if (!sv.recording) return;
    switch (local.op) {
    case CMD_DRAW_PRIMITIVE:
    case CMD_DRAW_INDEXED_PRIMITIVE: {
        VkViewport vp = {};
        vp.x = 0.0f; vp.y = 0.0f;
        vp.width  = (float)kRtWidth;
        vp.height = (float)kRtHeight;
        vp.minDepth = 0.0f; vp.maxDepth = 1.0f;
        vkCmdSetViewport(sv.secondary[sv.curIdx], 0, 1, &vp);
        ++g_vkCmdsThisFrame;
        break;
    }
    default:
        // State changes still just count. The translator phase puts real
        // vkCmd* here.
        break;
    }
}

bool AllocateSlotVulkanInfrastructure() {
    if (!g_vkReady) return true;   // Vulkan failed to boot — skip silently
    int allocatedPools = 0;
    int allocatedCbs   = 0;
    for (uint32_t i = 0; i < kMaxProducers; ++i) {
        SlotVulkan& sv = g_slotVulkan[i];

        VkCommandPoolCreateInfo pci = {};
        pci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
        // RESET_COMMAND_BUFFER_BIT lets us reset individual secondaries each
        // frame without resetting the entire pool. Saves a vkResetCommandPool
        // on the hot path.
        pci.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
        pci.queueFamilyIndex = g_vkGfxQueueFamily;
        if (vkCreateCommandPool(g_vkDevice, &pci, nullptr, &sv.pool) != VK_SUCCESS) {
            OD_LOG("[VkQ] vkCreateCommandPool(slot[%u]) failed", i);
            return false;
        }
        ++allocatedPools;

        VkCommandBufferAllocateInfo ai = {};
        ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        ai.commandPool = sv.pool;
        // Secondary level — these will be executed inside the primary CB's
        // render pass via vkCmdExecuteCommands. The per-slot drain threads
        // record into them in parallel.
        ai.level = VK_COMMAND_BUFFER_LEVEL_SECONDARY;
        ai.commandBufferCount = kVkFrameRing;
        if (vkAllocateCommandBuffers(g_vkDevice, &ai, sv.secondary) != VK_SUCCESS) {
            OD_LOG("[VkQ] vkAllocateCommandBuffers(slot[%u]) failed", i);
            return false;
        }
        allocatedCbs += kVkFrameRing;
    }
    OD_LOG("[VkQ] Phase B.2.1 per-slot Vulkan infrastructure READY: %d pools, "
           "%d secondary command buffers (kVkFrameRing=%d × kMaxProducers=%u). "
           "Cross-thread recording protocol activates in B.2.2.",
           allocatedPools, allocatedCbs, kVkFrameRing, kMaxProducers);
    return true;
}

void DestroySlotVulkanInfrastructure() {
    if (!g_vkDevice) return;
    for (uint32_t i = 0; i < kMaxProducers; ++i) {
        SlotVulkan& sv = g_slotVulkan[i];
        // Secondary CBs are freed automatically when the pool is destroyed.
        if (sv.pool) {
            vkDestroyCommandPool(g_vkDevice, sv.pool, nullptr);
            sv.pool = VK_NULL_HANDLE;
        }
        for (int k = 0; k < kVkFrameRing; ++k) sv.secondary[k] = VK_NULL_HANDLE;
        sv.curIdx = 0;
        sv.recording = false;
        sv.activeEpoch.store(0);
        sv.publishedEpoch.store(0);
        sv.publishedCb = VK_NULL_HANDLE;
    }
}

bool AllocateVkFrameRing() {
    VkCommandBufferAllocateInfo ai = {};
    ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    ai.commandPool = g_vkCmdPool;
    ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    ai.commandBufferCount = kVkFrameRing;
    if (vkAllocateCommandBuffers(g_vkDevice, &ai, g_vkCmdBuffers) != VK_SUCCESS) {
        OD_LOG("[VkQ] vkAllocateCommandBuffers (ring of %d) failed", kVkFrameRing);
        return false;
    }
    VkFenceCreateInfo fi = {};
    fi.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    fi.flags = VK_FENCE_CREATE_SIGNALED_BIT;   // start signaled = first acquire is free
    for (int i = 0; i < kVkFrameRing; ++i) {
        if (vkCreateFence(g_vkDevice, &fi, nullptr, &g_vkFences[i]) != VK_SUCCESS) {
            OD_LOG("[VkQ] vkCreateFence[%d] failed", i);
            return false;
        }
    }
    OD_LOG("[VkQ] Phase A.2 ring allocated: %d cmd buffers + %d fences",
           kVkFrameRing, kVkFrameRing);
    return true;
}

// Phase A.2: begin a fresh command buffer at the start of each "frame" of
// drained commands. We define a frame as either kCmdsPerSubmit drained
// commands OR an explicit END_SCENE. Whichever comes first triggers the
// submit. The cb is recycled via fence on the kVkFrameRing index.
constexpr uint64_t kCmdsPerSubmit = 8192;
bool             g_vkRecording = false;
// Mutex serializing primary-CB operations. Skyrim's Present caller can
// migrate threads (observed: tid=14804 → tid=14732 mid-session), which
// means BEGIN_SCENE/END_SCENE don't always land on the same producer slot.
// Whichever slot drain pops the frame-boundary cmd is now the one that
// opens / closes the primary CB; this mutex serializes those operations
// across slot drain threads.
std::mutex g_primaryMtx;
// Tracks which slot opened the current frame so SubmitVkFrame re-arms the
// correct slot's secondary at frame end. Read/written under g_primaryMtx.
int g_frameOpenerSlot = -1;

std::atomic<uint64_t> g_vkFenceWaits{0};

void BeginVkFrame(int callerSlotIdx) {
    std::lock_guard<std::mutex> lk(g_primaryMtx);
    if (!g_vkReady || g_vkRecording) return;
    int idx = g_vkFrameIdx;
    // Wait for the previous use of this slot to finish on the GPU. Bounded
    // wait (~5ms) so we don't deadlock the drain thread if the GPU is slow;
    // count fence waits so the periodic log surfaces backpressure.
    VkResult r = vkWaitForFences(g_vkDevice, 1, &g_vkFences[idx],
                                 VK_TRUE, 5'000'000);   // 5ms in nanoseconds
    if (r == VK_TIMEOUT) {
        // Slot still in use — skip this frame's recording rather than block.
        // (Indicates the kVkFrameRing depth is too low for current GPU lag.)
        g_vkFenceWaits.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    vkResetFences(g_vkDevice, 1, &g_vkFences[idx]);

    VkCommandBufferBeginInfo bi = {};
    bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if (vkBeginCommandBuffer(g_vkCmdBuffers[idx], &bi) != VK_SUCCESS) return;

    // Begin the offscreen render pass with a CLEAR to deep blue. Even with no
    // subsequent draws, the GPU executes the clear + image-layout transition
    // every frame — proves the full render-pass pipeline works.
    VkClearValue clear = {};
    clear.color.float32[0] = 0.05f;  // R
    clear.color.float32[1] = 0.10f;  // G
    clear.color.float32[2] = 0.20f;  // B
    clear.color.float32[3] = 1.0f;   // A

    VkRenderPassBeginInfo rpbi = {};
    rpbi.sType            = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
    rpbi.renderPass       = g_rtRenderPass;
    rpbi.framebuffer      = g_rtFramebuf;
    rpbi.renderArea.extent.width  = kRtWidth;
    rpbi.renderArea.extent.height = kRtHeight;
    rpbi.clearValueCount  = 1;
    rpbi.pClearValues     = &clear;

    // Phase B.2.2: render pass uses SECONDARY contents so we can stitch in
    // each slot's secondary CB via vkCmdExecuteCommands at SubmitVkFrame.
    vkCmdBeginRenderPass(g_vkCmdBuffers[idx], &rpbi,
                          VK_SUBPASS_CONTENTS_SECONDARY_COMMAND_BUFFERS);

    // Bump frame epoch — all slot drains will observe this on their next
    // loop iteration, end their in-flight secondary, and start a fresh one
    // for the new epoch. The CALLING slot's drain rolls its own secondary
    // synchronously here (same thread = safe to touch the pool); all other
    // slots roll on epoch observation in their own drain loops.
    uint64_t newEpoch = g_frameEpoch.fetch_add(1, std::memory_order_acq_rel) + 1;
    RollSecondaryToEpoch(callerSlotIdx, newEpoch);

    g_frameOpenerSlot = callerSlotIdx;
    g_vkRecording = true;
    g_vkCmdsThisFrame = 0;
}

// Phase B.2.2 stat: how many times SubmitVkFrame had to spin-wait for at
// least one slot to publish (i.e., a slot was lagging). High values mean
// some producer's drain isn't keeping up.
std::atomic<uint64_t> g_vkSlotWaits{0};

void SubmitVkFrame(int callerSlotIdx) {
    std::lock_guard<std::mutex> lk(g_primaryMtx);
    if (!g_vkReady || !g_vkRecording) return;
    int idx = g_vkFrameIdx;

    // Phase B.2.2 frame stitch:
    //   1. Bump epoch one more time so OTHER slots (1..hwm-1) will roll
    //      their secondaries and publish for the just-ended frame.
    //   2. End slot[0]'s own secondary and publish it (this thread owns it).
    //   3. Wait briefly for all slots to publish for `targetEpoch`.
    //   4. Gather the published CBs and vkCmdExecuteCommands them into the
    //      primary CB inside the render pass.
    //   5. End render pass, end primary, submit. Slot[0]'s secondary is
    //      re-armed at the end ready for the next frame.
    uint64_t finalEpoch  = g_frameEpoch.fetch_add(1, std::memory_order_acq_rel) + 1;
    uint64_t targetEpoch = finalEpoch - 1;

    // End the calling slot's secondary first (this thread owns its pool,
    // so the end+publish is safe). Other slots will observe the epoch and
    // publish on their own threads.
    EndAndPublishSecondary(callerSlotIdx);

    // Spin-wait with bounded timeout. 500us is enough at 1500 fps (~660us
    // per frame budget). The previous 2ms was holding g_primaryMtx too
    // long, blocking concurrent BeginVkFrame calls from other slot drains
    // (e.g., when render thread migrated mid-session, two drains would
    // both want frame-boundary access). Shorter timeout = less time
    // holding the mutex = less producer-side backpressure.
    uint32_t hwm = g_producerHWM.load(std::memory_order_acquire);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::microseconds(500);
    bool waited = false;
    for (uint32_t p = 1; p < hwm; ++p) {
        while (g_slotVulkan[p].publishedEpoch.load(std::memory_order_acquire) < targetEpoch) {
            if (std::chrono::steady_clock::now() > deadline) goto wait_done;
            _mm_pause();
            waited = true;
        }
    }
wait_done:
    if (waited) g_vkSlotWaits.fetch_add(1, std::memory_order_relaxed);

    // Gather all slots' published CBs at targetEpoch (or newer — a slot
    // racing ahead is fine, we still execute its frame-N work).
    VkCommandBuffer secondaries[kMaxProducers] = {};
    uint32_t secCount = 0;
    for (uint32_t p = 0; p < hwm; ++p) {
        SlotVulkan& sv = g_slotVulkan[p];
        if (sv.publishedEpoch.load(std::memory_order_acquire) >= targetEpoch &&
            sv.publishedCb != VK_NULL_HANDLE) {
            secondaries[secCount++] = sv.publishedCb;
        }
    }
    if (secCount > 0) {
        vkCmdExecuteCommands(g_vkCmdBuffers[idx], secCount, secondaries);
    }

    vkCmdEndRenderPass(g_vkCmdBuffers[idx]);
    vkEndCommandBuffer(g_vkCmdBuffers[idx]);

    VkSubmitInfo si = {};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &g_vkCmdBuffers[idx];

    if (vkQueueSubmit(g_vkGfxQueue, 1, &si, g_vkFences[idx]) == VK_SUCCESS) {
        ++g_vkSubmits;
    }
    g_vkRecording = false;
    g_vkFrameIdx = (g_vkFrameIdx + 1) % kVkFrameRing;

    // Re-arm the calling slot's secondary for the next frame's epoch.
    // activeEpoch is `finalEpoch` (the one just bumped to) — that slot's
    // next BEGIN_SCENE bumps again to finalEpoch+1 and rolls.
    SlotVulkan& svCaller = g_slotVulkan[callerSlotIdx];
    svCaller.curIdx = (svCaller.curIdx + 1) % kVkFrameRing;
    svCaller.activeEpoch.store(finalEpoch, std::memory_order_relaxed);
    BeginSecondary(callerSlotIdx);
    g_frameOpenerSlot = -1;
}

bool BootVulkan() {
    if (g_vkReady) return true;

    if (volkInitialize() != VK_SUCCESS) {
        OD_LOG("[VkQ] volkInitialize failed (no vulkan-1.dll on this system?)");
        return false;
    }

    VkApplicationInfo app = {};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "SkyrimRenderOverdrive";
    app.applicationVersion = 1;
    app.pEngineName = "VkQ Phase A";
    app.engineVersion = 1;
    app.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo ic = {};
    ic.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ic.pApplicationInfo = &app;
    // No extensions requested for Phase A — purely compute-style headless.
    // Surface/swapchain comes later when we actually want to display.

    if (vkCreateInstance(&ic, nullptr, &g_vkInstance) != VK_SUCCESS) {
        OD_LOG("[VkQ] vkCreateInstance failed");
        return false;
    }
    volkLoadInstance(g_vkInstance);

    // Pick a physical device. Prefer discrete GPU; fall back to first.
    uint32_t devCount = 0;
    vkEnumeratePhysicalDevices(g_vkInstance, &devCount, nullptr);
    if (devCount == 0) {
        OD_LOG("[VkQ] no Vulkan-capable physical devices found");
        return false;
    }
    std::vector<VkPhysicalDevice> devs(devCount);
    vkEnumeratePhysicalDevices(g_vkInstance, &devCount, devs.data());
    for (auto d : devs) {
        VkPhysicalDeviceProperties p;
        vkGetPhysicalDeviceProperties(d, &p);
        if (p.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
            g_vkPhysicalDevice = d;
            std::snprintf(g_vkDeviceName, sizeof(g_vkDeviceName), "%s", p.deviceName);
            break;
        }
    }
    if (g_vkPhysicalDevice == VK_NULL_HANDLE) {
        g_vkPhysicalDevice = devs[0];
        VkPhysicalDeviceProperties p;
        vkGetPhysicalDeviceProperties(g_vkPhysicalDevice, &p);
        std::snprintf(g_vkDeviceName, sizeof(g_vkDeviceName), "%s", p.deviceName);
    }

    // Find a graphics-capable queue family.
    uint32_t qfCount = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(g_vkPhysicalDevice, &qfCount, nullptr);
    std::vector<VkQueueFamilyProperties> qfs(qfCount);
    vkGetPhysicalDeviceQueueFamilyProperties(g_vkPhysicalDevice, &qfCount, qfs.data());
    bool foundGfx = false;
    for (uint32_t i = 0; i < qfCount; ++i) {
        if (qfs[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) {
            g_vkGfxQueueFamily = i;
            foundGfx = true;
            break;
        }
    }
    if (!foundGfx) {
        OD_LOG("[VkQ] no graphics queue family found on selected device");
        return false;
    }

    float prio = 1.0f;
    VkDeviceQueueCreateInfo qci = {};
    qci.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qci.queueFamilyIndex = g_vkGfxQueueFamily;
    qci.queueCount = 1;
    qci.pQueuePriorities = &prio;

    VkDeviceCreateInfo dci = {};
    dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;

    if (vkCreateDevice(g_vkPhysicalDevice, &dci, nullptr, &g_vkDevice) != VK_SUCCESS) {
        OD_LOG("[VkQ] vkCreateDevice failed");
        return false;
    }
    volkLoadDevice(g_vkDevice);
    vkGetDeviceQueue(g_vkDevice, g_vkGfxQueueFamily, 0, &g_vkGfxQueue);

    VkCommandPoolCreateInfo pci = {};
    pci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pci.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    pci.queueFamilyIndex = g_vkGfxQueueFamily;
    if (vkCreateCommandPool(g_vkDevice, &pci, nullptr, &g_vkCmdPool) != VK_SUCCESS) {
        OD_LOG("[VkQ] vkCreateCommandPool failed");
        return false;
    }

    g_vkReady = true;
    OD_LOG("[VkQ] Vulkan device READY: '%s' (queueFamily=%u). "
           "Phase A.1 complete: instance + device + graphics queue + cmd pool.",
           g_vkDeviceName, g_vkGfxQueueFamily);

    // Phase A.3c step 1: round-trip the minimal SPIR-V scaffold through the
    // driver. If vkCreateShaderModule accepts both modules, our SpirvBuilder
    // is producing structurally-valid binary — that's the prerequisite for
    // the opcode-by-opcode translator landing on top of it. Failure here
    // would point at incorrect SPIR-V layout, not at any DXBC translation
    // issue, so we want to know up-front before plumbing the parser through.
    {
        std::vector<uint32_t> vsMod = dxbc_spirv::EmitMinimalVS();
        std::vector<uint32_t> psMod = dxbc_spirv::EmitMinimalPS();
        VkShaderModuleCreateInfo smi = {};
        smi.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;

        VkShaderModule vs = VK_NULL_HANDLE;
        smi.codeSize = vsMod.size() * sizeof(uint32_t);
        smi.pCode    = vsMod.data();
        VkResult vr = vkCreateShaderModule(g_vkDevice, &smi, nullptr, &vs);
        if (vr == VK_SUCCESS) {
            OD_LOG("[VkQ] Phase A.3c-step1 minimal VS: vkCreateShaderModule OK "
                   "(%zu words, %zu bytes). Builder produces valid SPIR-V.",
                   vsMod.size(), vsMod.size() * sizeof(uint32_t));
            vkDestroyShaderModule(g_vkDevice, vs, nullptr);
        } else {
            OD_LOG("[VkQ] Phase A.3c-step1 minimal VS: vkCreateShaderModule "
                   "FAILED vr=%d (%zu words). SpirvBuilder layout incorrect.",
                   vr, vsMod.size());
        }

        VkShaderModule ps = VK_NULL_HANDLE;
        smi.codeSize = psMod.size() * sizeof(uint32_t);
        smi.pCode    = psMod.data();
        vr = vkCreateShaderModule(g_vkDevice, &smi, nullptr, &ps);
        if (vr == VK_SUCCESS) {
            OD_LOG("[VkQ] Phase A.3c-step1 minimal PS: vkCreateShaderModule OK "
                   "(%zu words, %zu bytes).",
                   psMod.size(), psMod.size() * sizeof(uint32_t));
            vkDestroyShaderModule(g_vkDevice, ps, nullptr);
        } else {
            OD_LOG("[VkQ] Phase A.3c-step1 minimal PS: vkCreateShaderModule "
                   "FAILED vr=%d (%zu words).", vr, psMod.size());
        }
    }

    // Phase A.3b: load (or initialize empty) the persistent pipeline cache
    // BEFORE any pipeline gets created. Pipelines created with this cache
    // benefit from previously-compiled state across sessions.
    if (!LoadPipelineCache()) {
        OD_LOG("[VkQ] pipeline cache init failed; pipelines will be uncached");
        // Non-fatal — pipelines still work, just slower to compile.
    }

    // Phase A.2: allocate the ring of command buffers + fences.
    if (!AllocateVkFrameRing()) {
        OD_LOG("[VkQ] Phase A.2 ring allocation failed; submission disabled");
        g_vkReady = false;   // disable Vulkan path; queue stays count-only
        return false;
    }
    if (!CreateOffscreenTarget()) {
        OD_LOG("[VkQ] Phase A.3a offscreen target setup failed; submission disabled");
        g_vkReady = false;
        return false;
    }
    OD_LOG("[VkQ] Phase A.3a ARMED. Drain thread now begins/ends a real render "
           "pass per Skyrim frame — GPU clears the offscreen image to deep blue "
           "every frame, validates the full Vulkan render-pass pipeline.");

    // Phase B.2.1 — allocate per-slot pools + secondary CBs ahead of any
    // producer registration. Pre-allocation means the drain threads can use
    // them immediately without locking on an "are pools ready yet" check.
    if (!AllocateSlotVulkanInfrastructure()) {
        OD_LOG("[VkQ] per-slot infrastructure setup failed; "
               "multi-thread CB recording disabled for this session");
        // Non-fatal — single-thread Vulkan path still works on slot[0].
    }

    // Live shader translator — register the ResourceMirror callback so
    // every D3D9 shader created from this point forward gets translated to
    // SPIR-V and a VkShaderModule cached on the spot. The cache is the
    // input to VkPipeline creation later in the rendering path.
    overdrive::resmirror::SetShaderCreatedCallback(LiveTranslateShaderCb);
    OD_LOG("[VkQ] Live shader translator armed: every D3D9 shader created "
           "from now on will be translated to SPIR-V and a VkShaderModule "
           "cached. Pass-rate reported in the periodic [VkQ] line.");
    return true;
}

void TeardownVulkan() {
    if (!g_vkReady && !g_vkInstance) return;
    // Unregister the live-translate callback BEFORE we tear down the device,
    // so any late shader creation between here and our return doesn't try
    // to call vkCreateShaderModule on a destroyed device.
    overdrive::resmirror::SetShaderCreatedCallback(nullptr);
    if (g_vkDevice) {
        // Wait for all in-flight submissions to finish before destroying.
        vkDeviceWaitIdle(g_vkDevice);
        DestroyLiveTranslatedModules();
        // Phase A.3b: persist the pipeline cache before tearing down. Must
        // happen before vkDestroyPipelineCache or the data is gone.
        SavePipelineCache();
        if (g_vkPipelineCache) {
            vkDestroyPipelineCache(g_vkDevice, g_vkPipelineCache, nullptr);
            g_vkPipelineCache = VK_NULL_HANDLE;
        }
        // Phase B.2.1 — tear down per-slot infrastructure before the device
        // goes away. Order matters: pools must be destroyed before the
        // device, and after the drain threads have stopped (handled by
        // Shutdown above).
        DestroySlotVulkanInfrastructure();
        DestroyOffscreenTarget();
        for (int i = 0; i < kVkFrameRing; ++i) {
            if (g_vkFences[i]) {
                vkDestroyFence(g_vkDevice, g_vkFences[i], nullptr);
                g_vkFences[i] = VK_NULL_HANDLE;
            }
        }
    }
    if (g_vkCmdPool) vkDestroyCommandPool(g_vkDevice, g_vkCmdPool, nullptr);
    if (g_vkDevice)  vkDestroyDevice(g_vkDevice, nullptr);
    if (g_vkInstance) vkDestroyInstance(g_vkInstance, nullptr);
    g_vkCmdPool = VK_NULL_HANDLE;
    g_vkDevice = VK_NULL_HANDLE;
    g_vkInstance = VK_NULL_HANDLE;
    g_vkPhysicalDevice = VK_NULL_HANDLE;
    g_vkGfxQueue = VK_NULL_HANDLE;
    g_vkReady = false;
}

std::chrono::steady_clock::time_point g_lastLog;
uint32_t g_lastPushed = 0;
uint32_t g_lastPopped = 0;
uint32_t g_lastDropped = 0;

// Phase B.2.2 (post-fix): process one drained cmd. Frame boundaries are
// handled by WHICHEVER slot drain pops them — Skyrim's Present caller can
// migrate threads, so we can't bind frame ownership to slot 0. The mutex
// inside BeginVkFrame/SubmitVkFrame serializes the primary CB ops; the
// caller passes its own slotIdx so its OWN secondary gets rolled (Vulkan
// pools are externally synced — only the owning thread can touch its pool).
static inline void ProcessDrainedCmd(int slotIdx, const Cmd& local) {
    if (!g_vkReady) return;
    switch (local.op) {
    case CMD_BEGIN_SCENE:
        BeginVkFrame(slotIdx);
        return;
    case CMD_END_SCENE:
        if (g_vkRecording) SubmitVkFrame(slotIdx);
        return;
    }
    // Non-frame-boundary cmds get recorded into the slot's own secondary.
    RecordCmdIntoSecondary(slotIdx, local);
}

// Per-slot drain thread. Each producer slot, once claimed, spawns one of
// these. It drains ONLY its own slot's ring — true CPU-level parallelism
// vs. the old single-drain round-robin design. Slot 0's drain handles the
// Vulkan render-pass + submit (BEGIN_SCENE/END_SCENE/draws come from the
// render thread, which always claims slot 0 first); other slots' drains
// only count their cmds for now (full per-slot Vulkan secondary command
// buffer recording lands in Phase B.2.1).
DWORD WINAPI PerSlotDrainProc(LPVOID userData) {
    int slotIdx = static_cast<int>(reinterpret_cast<intptr_t>(userData));
    ProducerRing& r = g_producers[slotIdx];
    OD_LOG("[VkQ] per-slot drain[%d] started tid=%lu (Phase B.2.2 — owns "
           "ring[%d], %s)",
           slotIdx, GetCurrentThreadId(), slotIdx,
           slotIdx == 0 ? "Vulkan recorder + frame coordinator"
                        : "Vulkan secondary CB recorder");

    // Phase B.2.2: each slot's drain begins its first secondary CB up front
    // so it's always in a "ready to record" state. activeEpoch starts at 0
    // (matches g_frameEpoch initial value); the first BEGIN_SCENE rolls it.
    g_slotVulkan[slotIdx].activeEpoch.store(0, std::memory_order_relaxed);
    BeginSecondary(slotIdx);

    while (!gShouldExit.load(std::memory_order_relaxed) &&
           !g_stopRequested.load(std::memory_order_relaxed)) {
        // Epoch check at OUTER loop boundary only (was: per-cmd). Per-cmd
        // checks revealed a worse problem in the log — drain throughput
        // dropped enough that the ring filled and we started dropping
        // cmds (dropped=41865 observed). Moving the check out of the hot
        // inner loop trades a bit of epoch latency (~13µs at 256-cmd batches
        // × 50ns/cmd) for ~4x faster drain. The 32K-entry ring absorbs the
        // resulting epoch slack.
        if (slotIdx > 0) {
            uint64_t global = g_frameEpoch.load(std::memory_order_acquire);
            uint64_t mine   = g_slotVulkan[slotIdx].activeEpoch.load(std::memory_order_relaxed);
            if (mine < global) {
                RollSecondaryToEpoch(slotIdx, global);
            }
        }

        int batched = 0;
        while (batched < 256) {
            uint32_t tail = r.tail.load(std::memory_order_relaxed);
            uint32_t head = r.head.load(std::memory_order_acquire);
            if (tail == head) break;
            Cmd local = r.ring[tail & ProducerRing::kMask];
            r.tail.store(tail + 1, std::memory_order_release);
            r.popped.fetch_add(1, std::memory_order_relaxed);
            g_popped.fetch_add(1, std::memory_order_relaxed);
            if (local.op < CMD_COUNT_) ++r.opCount[local.op];
            ProcessDrainedCmd(slotIdx, local);
            ++batched;
        }
        if (batched == 0) SwitchToThread();
    }

    // Final cleanup: end any in-flight secondary so the pool is clean for
    // destruction. If this drain happens to be the one that opened the
    // current frame, also submit that last frame.
    EndAndPublishSecondary(slotIdx);
    if (g_vkReady && g_vkRecording && g_frameOpenerSlot == slotIdx) {
        SubmitVkFrame(slotIdx);
    }

    // Final per-slot breakdown — only slot 0 prints global totals; each
    // slot prints its own opcode histogram.
    if (slotIdx == 0) {
        OD_LOG("[VkQ] per-slot drain[0] exiting. Total popped=%llu, dropped=%llu",
               (unsigned long long)g_popped.load(),
               (unsigned long long)g_dropped.load());
    }
    static const char* kOpNames[CMD_COUNT_] = {
        "NONE",
        "SET_RENDER_STATE", "SET_TEXTURE", "SET_VERTEX_SHADER",
        "SET_PIXEL_SHADER", "SET_VS_CONSTANT_F", "SET_PS_CONSTANT_F",
        "SET_STREAM_SOURCE", "SET_INDICES", "DRAW_PRIMITIVE",
        "DRAW_INDEXED_PRIMITIVE", "BEGIN_SCENE", "END_SCENE", "CLEAR",
    };
    for (int i = 1; i < CMD_COUNT_; ++i) {
        if (r.opCount[i]) {
            OD_LOG("[VkQ]   slot[%d] final cmd[%-22s] = %llu",
                   slotIdx, kOpNames[i], (unsigned long long)r.opCount[i]);
        }
    }
    return 0;
}

}  // namespace

bool Install() {
    // Reset all per-producer ring state (slots start free, indices start 0).
    for (uint32_t i = 0; i < kMaxProducers; ++i) {
        g_producers[i].head.store(0, std::memory_order_relaxed);
        g_producers[i].tail.store(0, std::memory_order_relaxed);
        g_producers[i].ownerTid.store(0, std::memory_order_relaxed);
        g_producers[i].pushed.store(0, std::memory_order_relaxed);
        g_producers[i].popped.store(0, std::memory_order_relaxed);
        g_producers[i].drainThread = nullptr;
        g_producers[i].drainThreadId = 0;
    }
    g_producerHWM.store(0);
    g_pushed.store(0); g_popped.store(0); g_dropped.store(0);
    g_stopRequested.store(false);

    // Phase A.1: boot Vulkan instance + device. Non-fatal if it fails (e.g.,
    // no vulkan-1.dll on the system) — the queue still works in count-only
    // mode for throughput validation.
    if (!BootVulkan()) {
        OD_LOG("[VkQ] Vulkan boot failed — running queue in count-only mode");
    }

    g_lastLog = std::chrono::steady_clock::now();
    OD_LOG("[VkQ] Installed (Phase B.2 multi-producer + per-slot drains). "
           "%u slots × %u entries (%u bytes/slot, %u bytes total), "
           "vulkan_ready=%s. Each producer thread auto-claims a slot AND "
           "spawns its own dedicated drain thread on first push — true "
           "multi-core CPU parallelism with zero cross-producer contention.",
           kMaxProducers, ProducerRing::kSize,
           (unsigned)(ProducerRing::kSize * sizeof(Cmd)),
           (unsigned)(kMaxProducers * ProducerRing::kSize * sizeof(Cmd)),
           g_vkReady ? "YES" : "no");
    return true;
}

void Shutdown() {
    g_stopRequested.store(true, std::memory_order_release);
    // Wait for every spawned per-slot drain thread to exit. Slots that
    // were never claimed have drainThread==nullptr and are skipped.
    for (uint32_t i = 0; i < kMaxProducers; ++i) {
        HANDLE h = g_producers[i].drainThread;
        if (h) {
            WaitForSingleObject(h, 1000);
            CloseHandle(h);
            g_producers[i].drainThread = nullptr;
        }
    }
    TeardownVulkan();
}

namespace {
// Try to claim a free producer slot for the calling thread. Returns the
// slot index (0..kMaxProducers-1) on success, or -1 if all are taken.
// Sticky: once claimed, the slot remains owned by this thread until
// ReleaseProducerSlot() is called explicitly. Slots that out-live their
// thread leak harmlessly — drain still works, the entries just go unused.
int RegisterProducerSlot() {
    if (tl_producerSlot >= 0) return tl_producerSlot;
    DWORD tid = GetCurrentThreadId();
    for (uint32_t i = 0; i < kMaxProducers; ++i) {
        uint32_t expected = 0;
        if (g_producers[i].ownerTid.compare_exchange_strong(
                expected, tid,
                std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            tl_producerSlot = static_cast<int>(i);
            // Bump high-water mark monotonically.
            uint32_t old = g_producerHWM.load(std::memory_order_relaxed);
            uint32_t want = i + 1;
            while (old < want) {
                if (g_producerHWM.compare_exchange_weak(
                        old, want,
                        std::memory_order_release,
                        std::memory_order_relaxed)) break;
            }
            // Phase B.2 — spawn this slot's dedicated drain thread. Slot 0's
            // drain runs the Vulkan render-pass logic (BEGIN/END_SCENE come
            // from the render thread, which always claims slot 0 first);
            // other slots just count their cmds today, will record into per-
            // slot secondary CBs in B.2.1.
            HANDLE drain = CreateThread(
                nullptr, 0,
                PerSlotDrainProc,
                reinterpret_cast<LPVOID>(static_cast<intptr_t>(i)),
                0, &g_producers[i].drainThreadId);
            if (drain) {
                // Slot 0 (Vulkan recorder) gets normal priority so frame
                // submits aren't starved; non-render-path slots run at
                // BELOW_NORMAL like the old single drain.
                SetThreadPriority(drain,
                    i == 0 ? THREAD_PRIORITY_NORMAL : THREAD_PRIORITY_BELOW_NORMAL);
                g_producers[i].drainThread = drain;
            } else {
                OD_LOG("[VkQ] failed to spawn drain thread for slot[%u]: err=%lu",
                       i, GetLastError());
            }
            OD_LOG("[VkQ] producer slot[%u] claimed by tid=%lu (%u/%u in use), "
                   "drain tid=%lu", i, tid, want, kMaxProducers,
                   (unsigned long)g_producers[i].drainThreadId);
            return static_cast<int>(i);
        }
    }
    return -1;
}
}  // namespace

bool Push(const Cmd& c) {
    int slot = tl_producerSlot;
    if (slot < 0) {
        slot = RegisterProducerSlot();
        if (slot < 0) {
            // All slots taken — drop. In practice we never hit this with
            // kMaxProducers=8 because Skyrim has ~7 active threads total.
            g_dropped.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }
    ProducerRing& r = g_producers[slot];
    uint32_t head = r.head.load(std::memory_order_relaxed);
    uint32_t tail = r.tail.load(std::memory_order_acquire);
    if (head - tail >= ProducerRing::kSize) {
        g_dropped.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    r.ring[head & ProducerRing::kMask] = c;
    r.head.store(head + 1, std::memory_order_release);
    r.pushed.fetch_add(1, std::memory_order_relaxed);
    g_pushed.fetch_add(1, std::memory_order_relaxed);
    return true;
}

void ReleaseProducerSlot() {
    if (tl_producerSlot < 0) return;
    g_producers[tl_producerSlot].ownerTid.store(0, std::memory_order_release);
    tl_producerSlot = -1;
}

bool PushOp1(uint8_t op, uint32_t a0) {
    Cmd c{};
    c.op = op; c.args[0] = a0;
    return Push(c);
}
bool PushOp2(uint8_t op, uint32_t a0, uint32_t a1) {
    Cmd c{};
    c.op = op; c.args[0] = a0; c.args[1] = a1;
    return Push(c);
}
bool PushOp3(uint8_t op, uint32_t a0, uint32_t a1, uint32_t a2) {
    Cmd c{};
    c.op = op; c.args[0] = a0; c.args[1] = a1; c.args[2] = a2;
    return Push(c);
}
bool PushOp4(uint8_t op, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3) {
    Cmd c{};
    c.op = op; c.args[0] = a0; c.args[1] = a1; c.args[2] = a2; c.args[3] = a3;
    return Push(c);
}

// Per-producer push deltas, retained across calls to compute /s rates.
uint32_t g_lastProducerPushed[kMaxProducers] = {};

void MaybeLogStats() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog);
    if (elapsed.count() < 5000) return;
    g_lastLog = now;

    uint32_t pushed  = g_pushed.load(std::memory_order_relaxed);
    uint32_t popped  = g_popped.load(std::memory_order_relaxed);
    uint32_t dropped = g_dropped.load(std::memory_order_relaxed);

    // Aggregate ring depth across all producers.
    uint32_t totalDepth = 0;
    uint32_t hwm = g_producerHWM.load(std::memory_order_acquire);
    for (uint32_t i = 0; i < hwm; ++i) {
        uint32_t h = g_producers[i].head.load(std::memory_order_relaxed);
        uint32_t t = g_producers[i].tail.load(std::memory_order_relaxed);
        totalDepth += (h - t);
    }

    uint32_t pushDelta = pushed - g_lastPushed;
    uint32_t popDelta  = popped - g_lastPopped;
    uint32_t dropDelta = dropped - g_lastDropped;
    g_lastPushed = pushed; g_lastPopped = popped; g_lastDropped = dropped;

    if (pushDelta == 0 && popDelta == 0) return;  // nothing happened

    uint64_t vkSubmits     = g_vkSubmits;
    uint64_t vkSubmitDelta = vkSubmits - g_vkLastSubmits;
    g_vkLastSubmits = vkSubmits;
    uint64_t vkFenceWaits  = g_vkFenceWaits.load(std::memory_order_relaxed);

    double secs = elapsed.count() / 1000.0;
    uint32_t totalCap = hwm * ProducerRing::kSize;
    double depthPct = totalCap > 0 ? (100.0 * totalDepth) / totalCap : 0.0;
    uint64_t vkSlotWaits = g_vkSlotWaits.load(std::memory_order_relaxed);
    OD_LOG("[VkQ] last %.1fs: pushed=%llu (%.0f/s) popped=%llu (%.0f/s) "
           "dropped=%llu depth=%u/%u (%.1f%%) producers=%u/%u "
           "vkSubmits=%llu (%.0f/s) vkFenceWaits=%llu vkSlotWaits=%llu epoch=%llu",
           secs,
           (unsigned long long)pushDelta, pushDelta / secs,
           (unsigned long long)popDelta,  popDelta  / secs,
           (unsigned long long)dropDelta,
           totalDepth, totalCap, depthPct,
           hwm, kMaxProducers,
           (unsigned long long)vkSubmitDelta, vkSubmitDelta / secs,
           (unsigned long long)vkFenceWaits,
           (unsigned long long)vkSlotWaits,
           (unsigned long long)g_frameEpoch.load(std::memory_order_relaxed));

    // Live translator pass-rate — every shader Skyrim creates goes through
    // DxbcToSpirv::Translate + vkCreateShaderModule. This number rising
    // toward total-shader-count = translator coverage is good enough for
    // the next phase (VkPipeline factory).
    uint32_t vsTried = g_xlat.vsTried.load(std::memory_order_relaxed);
    uint32_t vsOk    = g_xlat.vsOk.load(std::memory_order_relaxed);
    uint32_t psTried = g_xlat.psTried.load(std::memory_order_relaxed);
    uint32_t psOk    = g_xlat.psOk.load(std::memory_order_relaxed);
    if (vsTried > 0 || psTried > 0) {
        uint32_t vsDelta = vsOk - g_xlat.lastLogVsOk;
        uint32_t psDelta = psOk - g_xlat.lastLogPsOk;
        g_xlat.lastLogVsOk = vsOk;
        g_xlat.lastLogPsOk = psOk;
        // Real vs passthrough split: real = translator's opcode allowlist
        // matched; passthrough = fell back to EmitMinimalVS/PS (cache still
        // populates, but the actual pipeline output won't be correct
        // for that shader).
        uint32_t realCnt = overdrive::dxbc_spirv::TranslatedRealCount();
        uint32_t passCnt = overdrive::dxbc_spirv::TranslatedPassthroughCount();
        OD_LOG("[LiveXlat] VS=%u/%u (%.0f%%, +%u)  PS=%u/%u (%.0f%%, +%u)  "
               "real=%u  passthrough=%u  modules cached=%u",
               vsOk, vsTried, vsTried ? (100.0 * vsOk / vsTried) : 0.0, vsDelta,
               psOk, psTried, psTried ? (100.0 * psOk / psTried) : 0.0, psDelta,
               realCnt, passCnt, vsOk + psOk);
        // Top fail buckets — what's gating real coverage. Sorted by count.
        // This is the actionable signal: each bucket is "if I implement this
        // feature, N more shaders will translate cleanly."
        if (!g_xlat.failBuckets.empty()) {
            std::vector<std::pair<std::string, uint32_t>> sorted;
            {
                std::lock_guard<std::mutex> lk(g_xlat.mtx);
                sorted.assign(g_xlat.failBuckets.begin(), g_xlat.failBuckets.end());
            }
            std::sort(sorted.begin(), sorted.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            size_t cap = sorted.size() < 5 ? sorted.size() : 5;
            for (size_t i = 0; i < cap; ++i) {
                OD_LOG("[LiveXlat]   fail#%zu  count=%u  reason=\"%s\"",
                       i + 1, sorted[i].second, sorted[i].first.c_str());
            }
        }
    }

    // Per-slot breakdown — the actual multi-core signal. While Skyrim funnels
    // through D3D9's lock you'll see a single slot active. After we replace
    // D3D9, multiple slots should light up concurrently — that's the win.
    for (uint32_t i = 0; i < hwm; ++i) {
        uint32_t pp = g_producers[i].pushed.load(std::memory_order_relaxed);
        uint32_t delta = pp - g_lastProducerPushed[i];
        g_lastProducerPushed[i] = pp;
        if (delta == 0) continue;
        uint32_t tid = g_producers[i].ownerTid.load(std::memory_order_relaxed);
        uint32_t depth = g_producers[i].head.load(std::memory_order_relaxed)
                       - g_producers[i].tail.load(std::memory_order_relaxed);
        OD_LOG("[VkQ]   slot[%u] tid=%lu pushed=%llu (%.0f/s) depth=%u/%u",
               i, (unsigned long)tid,
               (unsigned long long)delta, delta / secs,
               depth, ProducerRing::kSize);
    }
}

}
