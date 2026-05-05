#pragma once

namespace overdrive::waitprof {

// Hook WaitForSingleObject (and ...Ex / WaitForMultipleObjects), bucket
// TESV.exe callers by call-site VA. The 58% of CPU time the page-histogram
// profiler showed in ntdll!ZwWaitForSingleObject originates here — these
// hooks tell us WHICH of TESV.exe's 45 wait sites are responsible.
//
// Each hook also records the dwMilliseconds passed in. dwMs=0xFFFFFFFF
// (INFINITE) indicates a true block — those are the call sites worth
// patching out / replacing with non-blocking variants.
//
// Returns true if at least one hook installed.
bool Install();

// Logs top hot wait callers (cumulative), throttled internally (15s).
void MaybeLogStats();

void Shutdown();

}
