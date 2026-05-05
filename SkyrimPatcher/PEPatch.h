#pragma once

#include <string>

namespace patcher {

// Adds an ".injsec" PE section to <exePath> containing a TLS callback that
// LoadLibraryA's <dllNameToLoad> on DLL_PROCESS_ATTACH. Modifies the PE in
// place. The exe must be PE32 (Win32), not /DYNAMICBASE, with no pre-existing
// non-empty TLS directory.
//
// Returns true on success.
bool AddInjsecAndTLS(const std::string& exePath, const std::string& dllNameToLoad);

// Zero PE TimeDateStamp and CheckSum fields (clean cosmetic markers).
bool ZeroChecksumAndTimestamp(const std::string& exePath);

}
