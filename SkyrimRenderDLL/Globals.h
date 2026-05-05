#pragma once

#include <atomic>
#include <string>

namespace overdrive {

inline std::atomic<bool> gShouldExit{false};

// Path to the directory containing TESV.exe — captured during DllMain so the
// worker thread can locate the log file and any future runtime assets.
inline std::string gSkyrimDir;

}
