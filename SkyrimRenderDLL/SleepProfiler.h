#pragma once

namespace overdrive::sleepprof {

// Hook kernel32!Sleep, record the caller's return address (which is the
// TESV.exe instruction immediately after the `call ds:Sleep` site), and
// bucket by call-site VA. After 60s of recording the dump shows the top
// N hottest Sleep callers — those are the ones to NOP / replace with PAUSE
// in the SkyrimPatcher EXE-patch step.
//
// Returns true if the hook was installed successfully.
bool Install();

// Logs top hot Sleep callers, throttled internally (15s).
void MaybeLogStats();

void Shutdown();

}
