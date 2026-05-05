#pragma once

#include <windows.h>

namespace overdrive {

// Worker entry point — runs in its own thread, OFF the loader lock.
// Owns SDL+Vulkan lifecycle for the lifetime of the process.
DWORD WINAPI BootstrapThreadProc(LPVOID userData);

}
