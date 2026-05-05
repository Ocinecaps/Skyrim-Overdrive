#include "VulkanWindow.h"
#include "DebugLogger.h"
#include "D3D9Hook.h"
#include "NiDX9Hooks.h"
#include "D3DXReplace.h"
#include "D3D9DeviceVtable.h"
#include "D3D9Mirror.h"

// volk is a meta-loader: it includes vulkan.h with VK_NO_PROTOTYPES set and
// provides volkInitializeCustom / volkLoadInstance / volkLoadDevice to
// populate function pointers at runtime via a vkGetInstanceProcAddr handler.
// This removes the need to link vulkan-1.lib (which LunarG no longer ships
// for Win32 since SDK 1.4.304.0).
#include "volk.h"

#include <SDL3/SDL.h>
#include <SDL3/SDL_vulkan.h>

#include <algorithm>
#include <vector>
#include <cstring>

namespace overdrive {

namespace {

// 860×360 ≈ 21:9 to match Skyrim's 3440×1440 ultrawide back buffer without
// horizontal squashing.
constexpr int          kWindowWidth      = 860;
constexpr int          kWindowHeight     = 360;

// Headless mode: create the window HIDDEN and skip vkQueuePresentKHR entirely.
// Reason: AMD Adrenalin / RTSS / GeForce Experience overlays attribute FPS to
// whichever swapchain they observe presenting. With our Vulkan swapchain
// presenting at 1000+ Hz, the overlay shows OUR frame rate, not Skyrim's.
// In headless mode we keep the Vulkan device + capture infrastructure (so
// future work like compute shaders for D3D9 helpers still has a home) but
// don't present anything from Vulkan. The overlay then has only Skyrim's
// D3D9 IDirect3DDevice9::Present to attribute to.
//
// Flip to false to bring the visible Vulkan window back for HUD / debug work.
constexpr bool         kHeadlessMode     = true;
constexpr VkClearValue kClearColor       = { { { 0.10f, 0.05f, 0.40f, 1.0f } } };
constexpr uint32_t     kInvalidQueueFamily = UINT32_MAX;

// Captured Skyrim frames are D3DFMT_X8R8G8B8 — bytes in memory are B,G,R,X.
// VK_FORMAT_B8G8R8A8_UNORM matches the byte order exactly (X is treated as
// alpha but we don't sample it).
constexpr VkFormat     kCaptureFormat    = VK_FORMAT_B8G8R8A8_UNORM;

// SPIR-V from glslc -mfmt=c. The .inc files are { 0x..., 0x..., ... } literals.
static const uint32_t kQuadVertSpv[] =
#include "Shaders/quad.vert.spv.inc"
;
static const uint32_t kQuadFragSpv[] =
#include "Shaders/quad.frag.spv.inc"
;

struct VulkanContext {
    VkInstance       instance         = VK_NULL_HANDLE;
    VkPhysicalDevice physicalDevice   = VK_NULL_HANDLE;
    uint32_t         graphicsFamily   = kInvalidQueueFamily;
    VkDevice         device           = VK_NULL_HANDLE;
    VkQueue          graphicsQueue    = VK_NULL_HANDLE;
    VkSurfaceKHR     surface          = VK_NULL_HANDLE;
    VkSwapchainKHR   swapchain        = VK_NULL_HANDLE;
    VkFormat         swapchainFormat  = VK_FORMAT_UNDEFINED;
    VkExtent2D       swapchainExtent  = {};
    std::vector<VkImage>       swapchainImages;
    std::vector<VkImageView>   swapchainViews;
    std::vector<VkFramebuffer> framebuffers;
    VkRenderPass     renderPass       = VK_NULL_HANDLE;
    VkCommandPool    cmdPool          = VK_NULL_HANDLE;
    std::vector<VkCommandBuffer> cmdBuffers;
    VkSemaphore      imageAvailable   = VK_NULL_HANDLE;
    VkSemaphore      renderFinished   = VK_NULL_HANDLE;
    VkFence          inFlight         = VK_NULL_HANDLE;

    // Phase 2.9 — texture for displaying captured Skyrim frames.
    VkImage          texImage         = VK_NULL_HANDLE;
    VkDeviceMemory   texMemory        = VK_NULL_HANDLE;
    VkImageView      texView          = VK_NULL_HANDLE;
    VkSampler        texSampler       = VK_NULL_HANDLE;
    uint32_t         texWidth         = 0;
    uint32_t         texHeight        = 0;
    VkImageLayout    texLayout        = VK_IMAGE_LAYOUT_UNDEFINED;
    bool             texEverUploaded  = false;

    // Staging buffer (host-visible, persistently mapped) for pixel uploads.
    VkBuffer         stagingBuffer    = VK_NULL_HANDLE;
    VkDeviceMemory   stagingMemory    = VK_NULL_HANDLE;
    void*            stagingMapped    = nullptr;
    VkDeviceSize     stagingCapacity  = 0;

    // Graphics pipeline for the textured fullscreen triangle.
    VkDescriptorSetLayout descLayout    = VK_NULL_HANDLE;
    VkDescriptorPool      descPool      = VK_NULL_HANDLE;
    VkDescriptorSet       descSet       = VK_NULL_HANDLE;
    VkPipelineLayout      pipelineLayout = VK_NULL_HANDLE;
    VkPipeline            pipeline      = VK_NULL_HANDLE;
    VkShaderModule        vertShader    = VK_NULL_HANDLE;
    VkShaderModule        fragShader    = VK_NULL_HANDLE;
    bool                  pipelineReady = false;

    // Latest captured frame index our worker has consumed.
    unsigned long long    lastSeenFrame = 0;
};

// ---------- Memory helpers ----------

uint32_t FindMemoryType(VkPhysicalDevice phys, uint32_t typeBits,
                        VkMemoryPropertyFlags wantFlags) {
    VkPhysicalDeviceMemoryProperties mem{};
    vkGetPhysicalDeviceMemoryProperties(phys, &mem);
    for (uint32_t i = 0; i < mem.memoryTypeCount; ++i) {
        if ((typeBits & (1u << i)) &&
            (mem.memoryTypes[i].propertyFlags & wantFlags) == wantFlags) {
            return i;
        }
    }
    return UINT32_MAX;
}

bool CreateBuffer(VulkanContext& vk, VkDeviceSize size, VkBufferUsageFlags usage,
                  VkMemoryPropertyFlags props,
                  VkBuffer& outBuf, VkDeviceMemory& outMem) {
    VkBufferCreateInfo bi{};
    bi.sType       = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bi.size        = size;
    bi.usage       = usage;
    bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(vk.device, &bi, nullptr, &outBuf) != VK_SUCCESS) return false;

    VkMemoryRequirements req{};
    vkGetBufferMemoryRequirements(vk.device, outBuf, &req);
    uint32_t typeIdx = FindMemoryType(vk.physicalDevice, req.memoryTypeBits, props);
    if (typeIdx == UINT32_MAX) return false;

    VkMemoryAllocateInfo ai{};
    ai.sType           = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ai.allocationSize  = req.size;
    ai.memoryTypeIndex = typeIdx;
    if (vkAllocateMemory(vk.device, &ai, nullptr, &outMem) != VK_SUCCESS) return false;
    if (vkBindBufferMemory(vk.device, outBuf, outMem, 0) != VK_SUCCESS) return false;
    return true;
}

bool CreateImage2D(VulkanContext& vk, uint32_t w, uint32_t h, VkFormat fmt,
                   VkImageUsageFlags usage,
                   VkImage& outImg, VkDeviceMemory& outMem) {
    VkImageCreateInfo ii{};
    ii.sType         = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO;
    ii.imageType     = VK_IMAGE_TYPE_2D;
    ii.format        = fmt;
    ii.extent        = { w, h, 1 };
    ii.mipLevels     = 1;
    ii.arrayLayers   = 1;
    ii.samples       = VK_SAMPLE_COUNT_1_BIT;
    ii.tiling        = VK_IMAGE_TILING_OPTIMAL;
    ii.usage         = usage;
    ii.sharingMode   = VK_SHARING_MODE_EXCLUSIVE;
    ii.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    if (vkCreateImage(vk.device, &ii, nullptr, &outImg) != VK_SUCCESS) return false;

    VkMemoryRequirements req{};
    vkGetImageMemoryRequirements(vk.device, outImg, &req);
    uint32_t typeIdx = FindMemoryType(vk.physicalDevice, req.memoryTypeBits,
                                      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if (typeIdx == UINT32_MAX) return false;

    VkMemoryAllocateInfo ai{};
    ai.sType           = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ai.allocationSize  = req.size;
    ai.memoryTypeIndex = typeIdx;
    if (vkAllocateMemory(vk.device, &ai, nullptr, &outMem) != VK_SUCCESS) return false;
    if (vkBindImageMemory(vk.device, outImg, outMem, 0) != VK_SUCCESS) return false;
    return true;
}

VkShaderModule MakeShader(VkDevice dev, const uint32_t* spirv, size_t bytes) {
    VkShaderModuleCreateInfo ci{};
    ci.sType    = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    ci.codeSize = bytes;
    ci.pCode    = spirv;
    VkShaderModule m = VK_NULL_HANDLE;
    if (vkCreateShaderModule(dev, &ci, nullptr, &m) != VK_SUCCESS) return VK_NULL_HANDLE;
    return m;
}

// ---------- Vulkan init (mostly unchanged from V1) ----------

bool CreateInstance(VulkanContext& vk) {
    Uint32 sdlExtCount = 0;
    const char* const* sdlExts = SDL_Vulkan_GetInstanceExtensions(&sdlExtCount);
    if (!sdlExts) {
        OD_LOG("[VK] SDL_Vulkan_GetInstanceExtensions failed: %s", SDL_GetError());
        return false;
    }
    std::vector<const char*> exts(sdlExts, sdlExts + sdlExtCount);

    VkApplicationInfo app{};
    app.sType              = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName   = "SkyrimRenderOverdrive";
    app.applicationVersion = VK_MAKE_VERSION(0, 1, 0);
    app.pEngineName        = "Overdrive";
    app.engineVersion      = VK_MAKE_VERSION(0, 1, 0);
    app.apiVersion         = VK_API_VERSION_1_2;

    VkInstanceCreateInfo ci{};
    ci.sType                   = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo        = &app;
    ci.enabledExtensionCount   = static_cast<uint32_t>(exts.size());
    ci.ppEnabledExtensionNames = exts.data();

    if (vkCreateInstance(&ci, nullptr, &vk.instance) != VK_SUCCESS) {
        OD_LOG("[VK] vkCreateInstance failed");
        return false;
    }
    volkLoadInstance(vk.instance);
    OD_LOG("[VK] instance created, %u extensions; instance-level functions loaded", sdlExtCount);
    return true;
}

bool PickPhysicalDevice(VulkanContext& vk) {
    uint32_t count = 0;
    vkEnumeratePhysicalDevices(vk.instance, &count, nullptr);
    if (count == 0) { OD_LOG("[VK] no physical devices"); return false; }
    std::vector<VkPhysicalDevice> devices(count);
    vkEnumeratePhysicalDevices(vk.instance, &count, devices.data());
    vk.physicalDevice = devices[0];

    VkPhysicalDeviceProperties props{};
    vkGetPhysicalDeviceProperties(vk.physicalDevice, &props);
    OD_LOG("[VK] picked physical device: %s", props.deviceName);

    uint32_t qCount = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(vk.physicalDevice, &qCount, nullptr);
    std::vector<VkQueueFamilyProperties> qProps(qCount);
    vkGetPhysicalDeviceQueueFamilyProperties(vk.physicalDevice, &qCount, qProps.data());
    for (uint32_t i = 0; i < qCount; ++i) {
        if (qProps[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) {
            VkBool32 ps = VK_FALSE;
            vkGetPhysicalDeviceSurfaceSupportKHR(vk.physicalDevice, i, vk.surface, &ps);
            if (ps) { vk.graphicsFamily = i; break; }
        }
    }
    if (vk.graphicsFamily == kInvalidQueueFamily) {
        OD_LOG("[VK] no graphics+present queue family");
        return false;
    }
    return true;
}

bool CreateLogicalDevice(VulkanContext& vk) {
    float prio = 1.0f;
    VkDeviceQueueCreateInfo qci{};
    qci.sType            = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qci.queueFamilyIndex = vk.graphicsFamily;
    qci.queueCount       = 1;
    qci.pQueuePriorities = &prio;

    const char* devExts[] = { VK_KHR_SWAPCHAIN_EXTENSION_NAME };
    VkDeviceCreateInfo ci{};
    ci.sType                   = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    ci.queueCreateInfoCount    = 1;
    ci.pQueueCreateInfos       = &qci;
    ci.enabledExtensionCount   = 1;
    ci.ppEnabledExtensionNames = devExts;

    if (vkCreateDevice(vk.physicalDevice, &ci, nullptr, &vk.device) != VK_SUCCESS) {
        OD_LOG("[VK] vkCreateDevice failed");
        return false;
    }
    volkLoadDevice(vk.device);
    vkGetDeviceQueue(vk.device, vk.graphicsFamily, 0, &vk.graphicsQueue);
    OD_LOG("[VK] device created; device-level functions loaded");
    return true;
}

bool CreateSwapchain(VulkanContext& vk) {
    VkSurfaceCapabilitiesKHR caps{};
    vkGetPhysicalDeviceSurfaceCapabilitiesKHR(vk.physicalDevice, vk.surface, &caps);
    uint32_t fmtCount = 0;
    vkGetPhysicalDeviceSurfaceFormatsKHR(vk.physicalDevice, vk.surface, &fmtCount, nullptr);
    std::vector<VkSurfaceFormatKHR> formats(fmtCount);
    vkGetPhysicalDeviceSurfaceFormatsKHR(vk.physicalDevice, vk.surface, &fmtCount, formats.data());

    VkSurfaceFormatKHR chosen = formats[0];
    for (const auto& f : formats) {
        if (f.format == VK_FORMAT_B8G8R8A8_UNORM &&
            f.colorSpace == VK_COLOR_SPACE_SRGB_NONLINEAR_KHR) {
            chosen = f; break;
        }
    }
    vk.swapchainFormat = chosen.format;

    VkExtent2D extent = caps.currentExtent;
    if (extent.width == 0xFFFFFFFF) {
        extent.width  = std::clamp<uint32_t>(kWindowWidth,  caps.minImageExtent.width,  caps.maxImageExtent.width);
        extent.height = std::clamp<uint32_t>(kWindowHeight, caps.minImageExtent.height, caps.maxImageExtent.height);
    }
    vk.swapchainExtent = extent;

    uint32_t imgCount = caps.minImageCount + 1;
    if (caps.maxImageCount > 0 && imgCount > caps.maxImageCount) imgCount = caps.maxImageCount;

    VkSwapchainCreateInfoKHR ci{};
    ci.sType            = VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR;
    ci.surface          = vk.surface;
    ci.minImageCount    = imgCount;
    ci.imageFormat      = chosen.format;
    ci.imageColorSpace  = chosen.colorSpace;
    ci.imageExtent      = extent;
    ci.imageArrayLayers = 1;
    ci.imageUsage       = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
    ci.imageSharingMode = VK_SHARING_MODE_EXCLUSIVE;
    ci.preTransform     = caps.currentTransform;
    ci.compositeAlpha   = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    ci.presentMode      = VK_PRESENT_MODE_FIFO_KHR;
    ci.clipped          = VK_TRUE;

    if (vkCreateSwapchainKHR(vk.device, &ci, nullptr, &vk.swapchain) != VK_SUCCESS) {
        OD_LOG("[VK] vkCreateSwapchainKHR failed");
        return false;
    }
    uint32_t actualCount = 0;
    vkGetSwapchainImagesKHR(vk.device, vk.swapchain, &actualCount, nullptr);
    vk.swapchainImages.resize(actualCount);
    vkGetSwapchainImagesKHR(vk.device, vk.swapchain, &actualCount, vk.swapchainImages.data());
    OD_LOG("[VK] swapchain created %ux%u, %u images", extent.width, extent.height, actualCount);
    return true;
}

bool CreateRenderPass(VulkanContext& vk) {
    VkAttachmentDescription color{};
    color.format         = vk.swapchainFormat;
    color.samples        = VK_SAMPLE_COUNT_1_BIT;
    color.loadOp         = VK_ATTACHMENT_LOAD_OP_CLEAR;
    color.storeOp        = VK_ATTACHMENT_STORE_OP_STORE;
    color.stencilLoadOp  = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    color.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    color.initialLayout  = VK_IMAGE_LAYOUT_UNDEFINED;
    color.finalLayout    = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;

    VkAttachmentReference ref{};
    ref.attachment = 0;
    ref.layout     = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;

    VkSubpassDescription sub{};
    sub.pipelineBindPoint    = VK_PIPELINE_BIND_POINT_GRAPHICS;
    sub.colorAttachmentCount = 1;
    sub.pColorAttachments    = &ref;

    VkSubpassDependency dep{};
    dep.srcSubpass    = VK_SUBPASS_EXTERNAL;
    dep.dstSubpass    = 0;
    dep.srcStageMask  = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    dep.dstStageMask  = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    dep.srcAccessMask = 0;
    dep.dstAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;

    VkRenderPassCreateInfo ci{};
    ci.sType           = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
    ci.attachmentCount = 1;
    ci.pAttachments    = &color;
    ci.subpassCount    = 1;
    ci.pSubpasses      = &sub;
    ci.dependencyCount = 1;
    ci.pDependencies   = &dep;
    return vkCreateRenderPass(vk.device, &ci, nullptr, &vk.renderPass) == VK_SUCCESS;
}

bool CreateImageViewsAndFramebuffers(VulkanContext& vk) {
    vk.swapchainViews.resize(vk.swapchainImages.size());
    vk.framebuffers.resize(vk.swapchainImages.size());
    for (size_t i = 0; i < vk.swapchainImages.size(); ++i) {
        VkImageViewCreateInfo vi{};
        vi.sType            = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
        vi.image            = vk.swapchainImages[i];
        vi.viewType         = VK_IMAGE_VIEW_TYPE_2D;
        vi.format           = vk.swapchainFormat;
        vi.subresourceRange = { VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1 };
        if (vkCreateImageView(vk.device, &vi, nullptr, &vk.swapchainViews[i]) != VK_SUCCESS) return false;

        VkFramebufferCreateInfo fi{};
        fi.sType           = VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO;
        fi.renderPass      = vk.renderPass;
        fi.attachmentCount = 1;
        fi.pAttachments    = &vk.swapchainViews[i];
        fi.width           = vk.swapchainExtent.width;
        fi.height          = vk.swapchainExtent.height;
        fi.layers          = 1;
        if (vkCreateFramebuffer(vk.device, &fi, nullptr, &vk.framebuffers[i]) != VK_SUCCESS) return false;
    }
    return true;
}

bool CreateCommandResources(VulkanContext& vk) {
    VkCommandPoolCreateInfo pi{};
    pi.sType            = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pi.flags            = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    pi.queueFamilyIndex = vk.graphicsFamily;
    if (vkCreateCommandPool(vk.device, &pi, nullptr, &vk.cmdPool) != VK_SUCCESS) return false;

    vk.cmdBuffers.resize(vk.framebuffers.size());
    VkCommandBufferAllocateInfo ai{};
    ai.sType              = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    ai.commandPool        = vk.cmdPool;
    ai.level              = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    ai.commandBufferCount = static_cast<uint32_t>(vk.cmdBuffers.size());
    if (vkAllocateCommandBuffers(vk.device, &ai, vk.cmdBuffers.data()) != VK_SUCCESS) return false;

    VkSemaphoreCreateInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
    VkFenceCreateInfo fi{};
    fi.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    fi.flags = VK_FENCE_CREATE_SIGNALED_BIT;
    if (vkCreateSemaphore(vk.device, &si, nullptr, &vk.imageAvailable) != VK_SUCCESS) return false;
    if (vkCreateSemaphore(vk.device, &si, nullptr, &vk.renderFinished) != VK_SUCCESS) return false;
    if (vkCreateFence(vk.device, &fi, nullptr, &vk.inFlight)               != VK_SUCCESS) return false;
    return true;
}

// ---------- Phase 2.9 — texture, staging, pipeline ----------

bool EnsureStagingBuffer(VulkanContext& vk, VkDeviceSize needed) {
    if (vk.stagingBuffer && vk.stagingCapacity >= needed) return true;
    if (vk.stagingMapped) {
        vkUnmapMemory(vk.device, vk.stagingMemory);
        vk.stagingMapped = nullptr;
    }
    if (vk.stagingBuffer) { vkDestroyBuffer(vk.device, vk.stagingBuffer, nullptr); vk.stagingBuffer = VK_NULL_HANDLE; }
    if (vk.stagingMemory) { vkFreeMemory(vk.device, vk.stagingMemory, nullptr); vk.stagingMemory = VK_NULL_HANDLE; }

    if (!CreateBuffer(vk, needed,
                      VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                      vk.stagingBuffer, vk.stagingMemory)) {
        OD_LOG("[VK] staging buffer alloc failed (size=%llu)", (unsigned long long)needed);
        return false;
    }
    vkMapMemory(vk.device, vk.stagingMemory, 0, needed, 0, &vk.stagingMapped);
    vk.stagingCapacity = needed;
    OD_LOG("[VK] staging buffer ready (capacity=%llu bytes)", (unsigned long long)vk.stagingCapacity);
    return true;
}

bool CreateTextureResources(VulkanContext& vk, uint32_t w, uint32_t h) {
    if (vk.texImage)   { vkDestroyImage(vk.device, vk.texImage, nullptr);     vk.texImage = VK_NULL_HANDLE; }
    if (vk.texView)    { vkDestroyImageView(vk.device, vk.texView, nullptr);  vk.texView  = VK_NULL_HANDLE; }
    if (vk.texMemory)  { vkFreeMemory(vk.device, vk.texMemory, nullptr);      vk.texMemory = VK_NULL_HANDLE; }

    if (!CreateImage2D(vk, w, h, kCaptureFormat,
                       VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_SAMPLED_BIT,
                       vk.texImage, vk.texMemory)) {
        OD_LOG("[VK] texture image alloc failed (%ux%u)", w, h);
        return false;
    }

    VkImageViewCreateInfo vi{};
    vi.sType            = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    vi.image            = vk.texImage;
    vi.viewType         = VK_IMAGE_VIEW_TYPE_2D;
    vi.format           = kCaptureFormat;
    vi.subresourceRange = { VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1 };
    if (vkCreateImageView(vk.device, &vi, nullptr, &vk.texView) != VK_SUCCESS) return false;

    if (vk.texSampler == VK_NULL_HANDLE) {
        VkSamplerCreateInfo si{};
        si.sType        = VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO;
        si.magFilter    = VK_FILTER_LINEAR;
        si.minFilter    = VK_FILTER_LINEAR;
        si.mipmapMode   = VK_SAMPLER_MIPMAP_MODE_NEAREST;
        si.addressModeU = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
        si.addressModeV = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
        si.addressModeW = VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
        si.maxLod       = 0.0f;
        if (vkCreateSampler(vk.device, &si, nullptr, &vk.texSampler) != VK_SUCCESS) return false;
    }

    vk.texWidth        = w;
    vk.texHeight       = h;
    vk.texLayout       = VK_IMAGE_LAYOUT_UNDEFINED;
    vk.texEverUploaded = false;
    OD_LOG("[VK] texture resources ready (%ux%u, format=%d)", w, h, (int)kCaptureFormat);
    return true;
}

bool CreateDescriptorAndPipeline(VulkanContext& vk) {
    if (vk.pipelineReady) return true;

    // Descriptor set layout: 1 combined image sampler @ binding 0 in fragment.
    VkDescriptorSetLayoutBinding b{};
    b.binding         = 0;
    b.descriptorType  = VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER;
    b.descriptorCount = 1;
    b.stageFlags      = VK_SHADER_STAGE_FRAGMENT_BIT;

    VkDescriptorSetLayoutCreateInfo li{};
    li.sType        = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    li.bindingCount = 1;
    li.pBindings    = &b;
    if (vkCreateDescriptorSetLayout(vk.device, &li, nullptr, &vk.descLayout) != VK_SUCCESS) return false;

    VkDescriptorPoolSize ps{};
    ps.type            = VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER;
    ps.descriptorCount = 1;
    VkDescriptorPoolCreateInfo pi{};
    pi.sType         = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    pi.maxSets       = 1;
    pi.poolSizeCount = 1;
    pi.pPoolSizes    = &ps;
    if (vkCreateDescriptorPool(vk.device, &pi, nullptr, &vk.descPool) != VK_SUCCESS) return false;

    VkDescriptorSetAllocateInfo ai{};
    ai.sType              = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    ai.descriptorPool     = vk.descPool;
    ai.descriptorSetCount = 1;
    ai.pSetLayouts        = &vk.descLayout;
    if (vkAllocateDescriptorSets(vk.device, &ai, &vk.descSet) != VK_SUCCESS) return false;

    VkPipelineLayoutCreateInfo pli{};
    pli.sType          = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pli.setLayoutCount = 1;
    pli.pSetLayouts    = &vk.descLayout;
    if (vkCreatePipelineLayout(vk.device, &pli, nullptr, &vk.pipelineLayout) != VK_SUCCESS) return false;

    vk.vertShader = MakeShader(vk.device, kQuadVertSpv, sizeof(kQuadVertSpv));
    vk.fragShader = MakeShader(vk.device, kQuadFragSpv, sizeof(kQuadFragSpv));
    if (!vk.vertShader || !vk.fragShader) {
        OD_LOG("[VK] shader module creation failed");
        return false;
    }

    VkPipelineShaderStageCreateInfo stages[2]{};
    stages[0].sType  = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[0].stage  = VK_SHADER_STAGE_VERTEX_BIT;
    stages[0].module = vk.vertShader;
    stages[0].pName  = "main";
    stages[1].sType  = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[1].stage  = VK_SHADER_STAGE_FRAGMENT_BIT;
    stages[1].module = vk.fragShader;
    stages[1].pName  = "main";

    VkPipelineVertexInputStateCreateInfo vi{};
    vi.sType = VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO;
    // No vertex buffers — fullscreen triangle generated from gl_VertexIndex.

    VkPipelineInputAssemblyStateCreateInfo ia{};
    ia.sType    = VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO;
    ia.topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;

    VkViewport vp{};
    vp.width  = (float)vk.swapchainExtent.width;
    vp.height = (float)vk.swapchainExtent.height;
    vp.maxDepth = 1.0f;
    VkRect2D scissor{ {0,0}, vk.swapchainExtent };
    VkPipelineViewportStateCreateInfo vps{};
    vps.sType         = VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO;
    vps.viewportCount = 1;
    vps.pViewports    = &vp;
    vps.scissorCount  = 1;
    vps.pScissors     = &scissor;

    VkPipelineRasterizationStateCreateInfo rs{};
    rs.sType       = VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO;
    rs.polygonMode = VK_POLYGON_MODE_FILL;
    rs.cullMode    = VK_CULL_MODE_NONE;
    rs.frontFace   = VK_FRONT_FACE_COUNTER_CLOCKWISE;
    rs.lineWidth   = 1.0f;

    VkPipelineMultisampleStateCreateInfo ms{};
    ms.sType                = VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO;
    ms.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;

    VkPipelineColorBlendAttachmentState cba{};
    cba.colorWriteMask = VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT |
                         VK_COLOR_COMPONENT_B_BIT | VK_COLOR_COMPONENT_A_BIT;
    VkPipelineColorBlendStateCreateInfo cb{};
    cb.sType           = VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO;
    cb.attachmentCount = 1;
    cb.pAttachments    = &cba;

    VkGraphicsPipelineCreateInfo gpi{};
    gpi.sType               = VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO;
    gpi.stageCount          = 2;
    gpi.pStages             = stages;
    gpi.pVertexInputState   = &vi;
    gpi.pInputAssemblyState = &ia;
    gpi.pViewportState      = &vps;
    gpi.pRasterizationState = &rs;
    gpi.pMultisampleState   = &ms;
    gpi.pColorBlendState    = &cb;
    gpi.layout              = vk.pipelineLayout;
    gpi.renderPass          = vk.renderPass;
    gpi.subpass             = 0;
    if (vkCreateGraphicsPipelines(vk.device, VK_NULL_HANDLE, 1, &gpi, nullptr, &vk.pipeline) != VK_SUCCESS) {
        OD_LOG("[VK] vkCreateGraphicsPipelines failed");
        return false;
    }

    vk.pipelineReady = true;
    OD_LOG("[VK] graphics pipeline ready (textured quad)");
    return true;
}

void UpdateDescriptorForTexture(VulkanContext& vk) {
    VkDescriptorImageInfo info{};
    info.sampler     = vk.texSampler;
    info.imageView   = vk.texView;
    info.imageLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;

    VkWriteDescriptorSet w{};
    w.sType           = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    w.dstSet          = vk.descSet;
    w.dstBinding      = 0;
    w.descriptorType  = VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER;
    w.descriptorCount = 1;
    w.pImageInfo      = &info;
    vkUpdateDescriptorSets(vk.device, 1, &w, 0, nullptr);
}

void TransitionImage(VkCommandBuffer cmd, VkImage img,
                     VkImageLayout oldL, VkImageLayout newL,
                     VkPipelineStageFlags srcStage, VkPipelineStageFlags dstStage,
                     VkAccessFlags srcAccess, VkAccessFlags dstAccess) {
    VkImageMemoryBarrier b{};
    b.sType                       = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER;
    b.oldLayout                   = oldL;
    b.newLayout                   = newL;
    b.srcAccessMask               = srcAccess;
    b.dstAccessMask               = dstAccess;
    b.srcQueueFamilyIndex         = VK_QUEUE_FAMILY_IGNORED;
    b.dstQueueFamilyIndex         = VK_QUEUE_FAMILY_IGNORED;
    b.image                       = img;
    b.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    b.subresourceRange.levelCount = 1;
    b.subresourceRange.layerCount = 1;
    vkCmdPipelineBarrier(cmd, srcStage, dstStage, 0, 0, nullptr, 0, nullptr, 1, &b);
}

void RecordFrame(VulkanContext& vk, VkCommandBuffer cmd, uint32_t imgIndex,
                 bool uploadPending) {
    VkCommandBufferBeginInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    vkBeginCommandBuffer(cmd, &bi);

    if (uploadPending && vk.texImage) {
        // UNDEFINED (or SHADER_READ) -> TRANSFER_DST
        TransitionImage(cmd, vk.texImage,
            vk.texLayout, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
            VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT,
            0, VK_ACCESS_TRANSFER_WRITE_BIT);

        VkBufferImageCopy region{};
        region.imageSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        region.imageSubresource.layerCount = 1;
        region.imageExtent = { vk.texWidth, vk.texHeight, 1 };
        vkCmdCopyBufferToImage(cmd, vk.stagingBuffer, vk.texImage,
                               VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, 1, &region);

        TransitionImage(cmd, vk.texImage,
            VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL,
            VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_FRAGMENT_SHADER_BIT,
            VK_ACCESS_TRANSFER_WRITE_BIT, VK_ACCESS_SHADER_READ_BIT);
        vk.texLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
        vk.texEverUploaded = true;
    }

    VkRenderPassBeginInfo rpb{};
    rpb.sType             = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
    rpb.renderPass        = vk.renderPass;
    rpb.framebuffer       = vk.framebuffers[imgIndex];
    rpb.renderArea.extent = vk.swapchainExtent;
    rpb.clearValueCount   = 1;
    rpb.pClearValues      = &kClearColor;
    vkCmdBeginRenderPass(cmd, &rpb, VK_SUBPASS_CONTENTS_INLINE);

    if (vk.pipelineReady && vk.texEverUploaded) {
        vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, vk.pipeline);
        vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS,
                                vk.pipelineLayout, 0, 1, &vk.descSet, 0, nullptr);
        vkCmdDraw(cmd, 3, 1, 0, 0);  // fullscreen triangle
    }

    vkCmdEndRenderPass(cmd);
    vkEndCommandBuffer(cmd);
}

void Teardown(VulkanContext& vk) {
    if (vk.device) vkDeviceWaitIdle(vk.device);

    if (vk.pipeline)        vkDestroyPipeline(vk.device, vk.pipeline, nullptr);
    if (vk.pipelineLayout)  vkDestroyPipelineLayout(vk.device, vk.pipelineLayout, nullptr);
    if (vk.fragShader)      vkDestroyShaderModule(vk.device, vk.fragShader, nullptr);
    if (vk.vertShader)      vkDestroyShaderModule(vk.device, vk.vertShader, nullptr);
    if (vk.descPool)        vkDestroyDescriptorPool(vk.device, vk.descPool, nullptr);
    if (vk.descLayout)      vkDestroyDescriptorSetLayout(vk.device, vk.descLayout, nullptr);

    if (vk.texSampler)      vkDestroySampler(vk.device, vk.texSampler, nullptr);
    if (vk.texView)         vkDestroyImageView(vk.device, vk.texView, nullptr);
    if (vk.texImage)        vkDestroyImage(vk.device, vk.texImage, nullptr);
    if (vk.texMemory)       vkFreeMemory(vk.device, vk.texMemory, nullptr);

    if (vk.stagingMapped)   vkUnmapMemory(vk.device, vk.stagingMemory);
    if (vk.stagingBuffer)   vkDestroyBuffer(vk.device, vk.stagingBuffer, nullptr);
    if (vk.stagingMemory)   vkFreeMemory(vk.device, vk.stagingMemory, nullptr);

    if (vk.inFlight)       vkDestroyFence(vk.device, vk.inFlight, nullptr);
    if (vk.renderFinished) vkDestroySemaphore(vk.device, vk.renderFinished, nullptr);
    if (vk.imageAvailable) vkDestroySemaphore(vk.device, vk.imageAvailable, nullptr);
    if (vk.cmdPool)        vkDestroyCommandPool(vk.device, vk.cmdPool, nullptr);
    for (VkFramebuffer fb : vk.framebuffers) if (fb) vkDestroyFramebuffer(vk.device, fb, nullptr);
    for (VkImageView v : vk.swapchainViews) if (v) vkDestroyImageView(vk.device, v, nullptr);
    if (vk.renderPass) vkDestroyRenderPass(vk.device, vk.renderPass, nullptr);
    if (vk.swapchain)  vkDestroySwapchainKHR(vk.device, vk.swapchain, nullptr);
    if (vk.device)     vkDestroyDevice(vk.device, nullptr);
    if (vk.surface)    vkDestroySurfaceKHR(vk.instance, vk.surface, nullptr);
    if (vk.instance)   vkDestroyInstance(vk.instance, nullptr);
}

}  // namespace

bool RunVulkanWindow(std::atomic<bool>& shouldExit) {
    if (!SDL_Init(SDL_INIT_VIDEO)) {
        OD_LOG("[SDL] init failed: %s", SDL_GetError());
        return false;
    }
    OD_LOG("[SDL] init ok");

    // In headless mode the window is created HIDDEN — still needed so SDL3 can
    // create a Vulkan surface, but invisible to the user and to AMD's overlay
    // attribution. We further skip vkQueuePresentKHR below so the overlay sees
    // no Vulkan frames at all.
    SDL_WindowFlags flags = SDL_WINDOW_VULKAN;
    if (kHeadlessMode) flags |= SDL_WINDOW_HIDDEN;

    SDL_Window* window = SDL_CreateWindow(
        "Skyrim Render Overdrive",
        kWindowWidth, kWindowHeight, flags);
    if (!window) {
        OD_LOG("[SDL] CreateWindow failed: %s", SDL_GetError());
        SDL_Quit();
        return false;
    }
    OD_LOG("[SDL] window created %dx%d (hidden=%d, headless=%d) — "
           "AMD overlay will attribute FPS to Skyrim's D3D9 swapchain",
           kWindowWidth, kWindowHeight, kHeadlessMode, kHeadlessMode);

    PFN_vkGetInstanceProcAddr getInstanceProcAddr =
        reinterpret_cast<PFN_vkGetInstanceProcAddr>(SDL_Vulkan_GetVkGetInstanceProcAddr());
    if (!getInstanceProcAddr) {
        OD_LOG("[VK] SDL_Vulkan_GetVkGetInstanceProcAddr returned null: %s", SDL_GetError());
        SDL_DestroyWindow(window); SDL_Quit();
        return false;
    }
    volkInitializeCustom(getInstanceProcAddr);
    OD_LOG("[VK] volk initialized via SDL3 loader");

    VulkanContext vk{};

    auto bail = [&](const char* tag) {
        OD_LOG("[VK] init failed at %s", tag);
        Teardown(vk); SDL_DestroyWindow(window); SDL_Quit();
        return false;
    };

    if (!CreateInstance(vk))                                          return bail("CreateInstance");
    if (!SDL_Vulkan_CreateSurface(window, vk.instance, nullptr, &vk.surface)) return bail("CreateSurface");
    OD_LOG("[VK] surface created");
    if (!PickPhysicalDevice(vk))                                       return bail("PickPhysicalDevice");
    if (!CreateLogicalDevice(vk))                                      return bail("CreateLogicalDevice");
    if (!CreateSwapchain(vk))                                          return bail("CreateSwapchain");
    if (!CreateRenderPass(vk))                                         return bail("CreateRenderPass");
    if (!CreateImageViewsAndFramebuffers(vk))                          return bail("CreateImageViewsAndFramebuffers");
    if (!CreateCommandResources(vk))                                   return bail("CreateCommandResources");

    bool firstFrameLogged   = false;
    bool firstUploadLogged  = false;
    unsigned long long uploadCount = 0;

    while (!shouldExit.load(std::memory_order_relaxed)) {
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) { /* drain */ }

        // Phase 3 — emit periodic NiDX9 hook stats (internally throttled to 5s).
        nidx9::MaybeLogStats();
        // Phase 4 — periodic SSE replacement counters.
        d3dx::MaybeLogStats();
        // Phase 5 — periodic IDirect3DDevice9 vtable profile (top 10 hottest).
        d3d9vt::MaybeLogStats();
        // Phase 6 — typed-wrapper mirror state summary.
        mirror::MaybeLogStats();

        // ---------- Phase 2.9 — fetch + upload latest captured frame ----------
        d3d9hook::CapturedFrame frame;
        bool isNew = d3d9hook::TryGetLatestFrame(frame, vk.lastSeenFrame);
        bool uploadThisFrame = false;
        if (isNew && !frame.pixels.empty()) {
            // First frame ever, or resolution change: (re)allocate texture.
            if (!vk.texImage || vk.texWidth != frame.width || vk.texHeight != frame.height) {
                if (!CreateTextureResources(vk, frame.width, frame.height)) {
                    OD_LOG("[VK] CreateTextureResources failed");
                } else if (!CreateDescriptorAndPipeline(vk)) {
                    OD_LOG("[VK] CreateDescriptorAndPipeline failed");
                } else {
                    UpdateDescriptorForTexture(vk);
                }
            }
            // Upload pixels via staging buffer.
            if (vk.texImage && EnsureStagingBuffer(vk, frame.pixels.size())) {
                memcpy(vk.stagingMapped, frame.pixels.data(), frame.pixels.size());
                uploadThisFrame = true;
                ++uploadCount;
                if (!firstUploadLogged) {
                    OD_LOG("[VK] first frame uploaded (%ux%u, %zu bytes)",
                           frame.width, frame.height, frame.pixels.size());
                    firstUploadLogged = true;
                }
                if (uploadCount == 60 || uploadCount == 600 || (uploadCount % 6000) == 0) {
                    OD_LOG("[VK] uploaded #%llu (%ux%u)", uploadCount, frame.width, frame.height);
                }
            }
        }

        // ---------- standard acquire/record/submit/present ----------
        // In headless mode we do everything except touch the swapchain. This
        // keeps the upload pipeline healthy (texture copies still happen, so
        // future work that GPU-processes the captured frame still works) but
        // no Vulkan frame is ever presented → AMD overlay can't see us.
        if (kHeadlessMode) {
            // Light idle to avoid burning a core; capture rate is 20 fps so
            // a 50ms tick is plenty.
            SDL_Delay(50);
            continue;
        }

        vkWaitForFences(vk.device, 1, &vk.inFlight, VK_TRUE, UINT64_MAX);
        vkResetFences(vk.device, 1, &vk.inFlight);

        uint32_t imgIndex = 0;
        VkResult r = vkAcquireNextImageKHR(vk.device, vk.swapchain, UINT64_MAX,
                                           vk.imageAvailable, VK_NULL_HANDLE, &imgIndex);
        if (r == VK_ERROR_OUT_OF_DATE_KHR || r == VK_SUBOPTIMAL_KHR) continue;
        if (r != VK_SUCCESS) {
            OD_LOG("[VK] acquire failed code=%d, exiting render loop", r);
            break;
        }

        VkCommandBuffer cmd = vk.cmdBuffers[imgIndex];
        vkResetCommandBuffer(cmd, 0);
        RecordFrame(vk, cmd, imgIndex, uploadThisFrame);

        VkPipelineStageFlags wait = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
        VkSubmitInfo si{};
        si.sType                = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        si.waitSemaphoreCount   = 1;
        si.pWaitSemaphores      = &vk.imageAvailable;
        si.pWaitDstStageMask    = &wait;
        si.commandBufferCount   = 1;
        si.pCommandBuffers      = &cmd;
        si.signalSemaphoreCount = 1;
        si.pSignalSemaphores    = &vk.renderFinished;
        vkQueueSubmit(vk.graphicsQueue, 1, &si, vk.inFlight);

        VkPresentInfoKHR pi{};
        pi.sType              = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
        pi.waitSemaphoreCount = 1;
        pi.pWaitSemaphores    = &vk.renderFinished;
        pi.swapchainCount     = 1;
        pi.pSwapchains        = &vk.swapchain;
        pi.pImageIndices      = &imgIndex;
        vkQueuePresentKHR(vk.graphicsQueue, &pi);

        if (!firstFrameLogged) {
            OD_LOG("[VK] first frame presented");
            firstFrameLogged = true;
        }
    }

    Teardown(vk);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return true;
}

}  // namespace overdrive
