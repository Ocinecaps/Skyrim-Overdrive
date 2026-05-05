#pragma once

#include <string>
#include <vector>

namespace patcher {

struct SectionInfo {
    std::string name;
    unsigned long virtualAddress;
    unsigned long virtualSize;
    unsigned long pointerToRawData;
    unsigned long sizeOfRawData;
    unsigned long characteristics;
};

struct TlsInfo {
    bool        present                  = false;
    unsigned long directoryRVA           = 0;
    unsigned long directorySize          = 0;
    unsigned long startAddressOfRawData  = 0;
    unsigned long endAddressOfRawData    = 0;
    unsigned long addressOfIndex         = 0;
    unsigned long addressOfCallBacks     = 0;
    unsigned long sizeOfZeroFill         = 0;
    unsigned long characteristics        = 0;
    std::vector<unsigned long> callbacks;
};

struct ExeReport {
    bool                       valid           = false;
    std::string                error;
    unsigned long              imageBase       = 0;
    unsigned long              sizeOfImage     = 0;
    unsigned long              entryPointRVA   = 0;
    bool                       largeAddressAware = false;
    bool                       dynamicBase     = false;
    std::vector<SectionInfo>   sections;
    bool                       hasInjsec       = false;
    TlsInfo                    tls;
    bool                       referencesOurDll = false;  // .injsec contains our DLL string
    unsigned long              fileSizeBytes   = 0;
};

// Parse an exe and produce a structured report.
ExeReport InspectExe(const std::string& exePath);

// Render an ExeReport as multi-line human-readable text.
std::string FormatReport(const ExeReport& r);

// Compare exe to its `.original` backup; returns a short diff summary string.
// If no backup exists, returns "(no .original backup to diff against)".
std::string DiffAgainstOriginal(const std::string& exePath);

}
