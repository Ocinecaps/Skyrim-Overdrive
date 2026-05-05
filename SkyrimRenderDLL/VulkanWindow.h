#pragma once

#include <atomic>

namespace overdrive {

// Minimal SDL3+Vulkan window. V1 just clears to a known color and presents.
// Returns when shouldExit becomes true or an unrecoverable error occurs.
//
// Returns true if the window+device+swapchain were successfully created and
// at least one frame was presented; false if init failed (game continues
// without our overlay).
bool RunVulkanWindow(std::atomic<bool>& shouldExit);

}
