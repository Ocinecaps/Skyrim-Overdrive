#include "Inspector.h"
#include "Logging.h"

#include <windows.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace patcher {

namespace {

#pragma pack(push, 1)
struct ImageTlsDirectory32 {
    DWORD StartAddressOfRawData;
    DWORD EndAddressOfRawData;
    DWORD AddressOfIndex;
    DWORD AddressOfCallBacks;
    DWORD SizeOfZeroFill;
    DWORD Characteristics;
};
#pragma pack(pop)

DWORD RvaToFileOffset(DWORD rva, const std::vector<SectionInfo>& sections) {
    for (const auto& s : sections) {
        const DWORD vSize = s.virtualSize ? s.virtualSize : s.sizeOfRawData;
        if (rva >= s.virtualAddress && rva < s.virtualAddress + vSize) {
            return s.pointerToRawData + (rva - s.virtualAddress);
        }
    }
    return 0;
}

std::string FlagsToString(DWORD c) {
    std::string s;
    if (c & IMAGE_SCN_MEM_READ)    s += "R";
    if (c & IMAGE_SCN_MEM_WRITE)   s += "W";
    if (c & IMAGE_SCN_MEM_EXECUTE) s += "X";
    if (c & IMAGE_SCN_CNT_CODE)    s += "+code";
    if (c & IMAGE_SCN_CNT_INITIALIZED_DATA) s += "+init";
    return s.empty() ? "(none)" : s;
}

unsigned long FileSize(std::ifstream& f) {
    f.seekg(0, std::ios::end);
    auto p = f.tellg();
    f.seekg(0, std::ios::beg);
    return static_cast<unsigned long>(p);
}

// Read whole file into memory for diffing.
bool ReadAll(const std::string& path, std::vector<unsigned char>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    auto sz = static_cast<size_t>(f.tellg());
    f.seekg(0, std::ios::beg);
    out.resize(sz);
    if (sz) f.read(reinterpret_cast<char*>(out.data()), sz);
    return f.good() || f.eof();
}

}

ExeReport InspectExe(const std::string& exePath) {
    ExeReport r;

    std::ifstream f(exePath, std::ios::binary);
    if (!f) {
        r.error = "Cannot open file: " + exePath;
        return r;
    }
    r.fileSizeBytes = FileSize(f);

    IMAGE_DOS_HEADER dos{};
    f.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!f || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        r.error = "Bad DOS signature";
        return r;
    }

    f.seekg(dos.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS32 nt{};
    f.read(reinterpret_cast<char*>(&nt), sizeof(nt));
    if (!f || nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        r.error = "Not a PE32 image";
        return r;
    }

    r.valid             = true;
    r.imageBase         = nt.OptionalHeader.ImageBase;
    r.sizeOfImage       = nt.OptionalHeader.SizeOfImage;
    r.entryPointRVA     = nt.OptionalHeader.AddressOfEntryPoint;
    r.largeAddressAware = (nt.FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;
    r.dynamicBase       = (nt.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;

    const WORD secCount = nt.FileHeader.NumberOfSections;
    std::vector<IMAGE_SECTION_HEADER> raw(secCount);
    f.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(secCount) * sizeof(IMAGE_SECTION_HEADER));
    if (!f) {
        r.error = "Failed to read section headers";
        r.valid = false;
        return r;
    }

    r.sections.reserve(secCount);
    for (const auto& s : raw) {
        SectionInfo si;
        char name[9] = {};
        memcpy(name, s.Name, 8);
        si.name             = name;
        si.virtualAddress   = s.VirtualAddress;
        si.virtualSize      = s.Misc.VirtualSize;
        si.pointerToRawData = s.PointerToRawData;
        si.sizeOfRawData    = s.SizeOfRawData;
        si.characteristics  = s.Characteristics;
        r.sections.push_back(si);
        if (si.name == ".injsec") r.hasInjsec = true;
    }

    // TLS
    const DWORD tlsRVA  = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    const DWORD tlsSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    r.tls.directoryRVA  = tlsRVA;
    r.tls.directorySize = tlsSize;

    if (tlsRVA != 0 && tlsSize >= sizeof(ImageTlsDirectory32)) {
        const DWORD off = RvaToFileOffset(tlsRVA, r.sections);
        if (off != 0) {
            ImageTlsDirectory32 td{};
            f.clear();
            f.seekg(off, std::ios::beg);
            f.read(reinterpret_cast<char*>(&td), sizeof(td));
            if (f) {
                r.tls.present                 = true;
                r.tls.startAddressOfRawData   = td.StartAddressOfRawData;
                r.tls.endAddressOfRawData     = td.EndAddressOfRawData;
                r.tls.addressOfIndex          = td.AddressOfIndex;
                r.tls.addressOfCallBacks      = td.AddressOfCallBacks;
                r.tls.sizeOfZeroFill          = td.SizeOfZeroFill;
                r.tls.characteristics         = td.Characteristics;

                if (td.AddressOfCallBacks != 0 && td.AddressOfCallBacks > r.imageBase) {
                    DWORD cbOff = RvaToFileOffset(td.AddressOfCallBacks - r.imageBase, r.sections);
                    if (cbOff != 0) {
                        f.clear();
                        f.seekg(cbOff, std::ios::beg);
                        for (int i = 0; i < 64; ++i) {
                            DWORD ptr = 0;
                            f.read(reinterpret_cast<char*>(&ptr), sizeof(ptr));
                            if (!f || ptr == 0) break;
                            r.tls.callbacks.push_back(ptr);
                        }
                    }
                }
            }
        }
    }

    // Look for our DLL string inside .injsec section
    if (r.hasInjsec) {
        for (const auto& s : r.sections) {
            if (s.name == ".injsec") {
                std::vector<char> buf(s.sizeOfRawData);
                f.clear();
                f.seekg(s.pointerToRawData, std::ios::beg);
                f.read(buf.data(), buf.size());
                if (f) {
                    const char* needle = "SkyrimRenderOverdrive.dll";
                    for (size_t i = 0; i + strlen(needle) <= buf.size(); ++i) {
                        if (memcmp(buf.data() + i, needle, strlen(needle)) == 0) {
                            r.referencesOurDll = true;
                            break;
                        }
                    }
                }
                break;
            }
        }
    }

    return r;
}

std::string FormatReport(const ExeReport& r) {
    std::ostringstream o;
    o << std::hex << std::uppercase << std::setfill('0');

    if (!r.valid) {
        o << "INVALID PE: " << r.error;
        return o.str();
    }

    o << "File size:        " << std::dec << r.fileSizeBytes << " bytes\n"
      << "Image base:       0x" << std::hex << std::setw(8) << r.imageBase << "\n"
      << "Size of image:    0x" << std::setw(8) << r.sizeOfImage << "\n"
      << "Entry point RVA:  0x" << std::setw(8) << r.entryPointRVA << "\n"
      << "LargeAddrAware:   " << (r.largeAddressAware ? "yes" : "no") << "\n"
      << "DYNAMIC_BASE:     " << (r.dynamicBase ? "yes (ASLR enabled — bad for our patch)" : "no") << "\n"
      << "Has .injsec sec:  " << (r.hasInjsec ? "YES (already patched)" : "no (pristine layout)") << "\n"
      << "Has our DLL ref:  " << (r.referencesOurDll ? "YES" : "no") << "\n"
      << "Sections (" << std::dec << r.sections.size() << "):\n";
    for (const auto& s : r.sections) {
        o << std::hex << std::setfill('0')
          << "  " << std::setw(8) << s.name
          << "  va=0x" << std::setw(8) << s.virtualAddress
          << "  vsz=0x" << std::setw(6) << s.virtualSize
          << "  raw=0x" << std::setw(8) << s.pointerToRawData
          << "  rsz=0x" << std::setw(6) << s.sizeOfRawData
          << "  flags=" << FlagsToString(s.characteristics) << "\n";
    }

    o << "\nTLS directory:\n";
    if (!r.tls.present) {
        if (r.tls.directoryRVA == 0) {
            o << "  (none — DataDirectory[TLS] is empty)\n";
        } else {
            o << "  declared at RVA=0x" << std::hex << std::setw(8) << r.tls.directoryRVA
              << ", size=" << std::dec << r.tls.directorySize
              << " — but could not be read\n";
        }
    } else {
        o << std::hex << std::setfill('0')
          << "  Directory RVA:        0x" << std::setw(8) << r.tls.directoryRVA << "\n"
          << "  StartAddressOfRawData 0x" << std::setw(8) << r.tls.startAddressOfRawData << "\n"
          << "  EndAddressOfRawData   0x" << std::setw(8) << r.tls.endAddressOfRawData << "\n"
          << "  AddressOfIndex        0x" << std::setw(8) << r.tls.addressOfIndex << "\n"
          << "  AddressOfCallBacks    0x" << std::setw(8) << r.tls.addressOfCallBacks << "\n"
          << "  SizeOfZeroFill        " << std::dec << r.tls.sizeOfZeroFill << "\n"
          << "  Callbacks (" << r.tls.callbacks.size() << "):\n";
        for (size_t i = 0; i < r.tls.callbacks.size(); ++i) {
            o << "    [" << i << "] 0x" << std::hex << std::setw(8) << std::setfill('0')
              << r.tls.callbacks[i] << "\n";
        }
    }

    return o.str();
}

std::string DiffAgainstOriginal(const std::string& exePath) {
    const std::string backup = exePath + ".original";
    if (GetFileAttributesA(backup.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return "(no .original backup to diff against)";
    }

    std::vector<unsigned char> a, b;
    if (!ReadAll(exePath, a)) return "Failed to read current exe";
    if (!ReadAll(backup, b))  return "Failed to read .original backup";

    std::ostringstream o;
    o << "Current size:  " << a.size() << " bytes\n"
      << ".original size: " << b.size() << " bytes\n"
      << "Delta:          " << static_cast<long long>(a.size()) - static_cast<long long>(b.size())
      << " bytes\n\n";

    const size_t common = a.size() < b.size() ? a.size() : b.size();
    size_t diffBytes = 0;
    size_t firstDiff = static_cast<size_t>(-1);
    size_t lastDiff  = 0;
    for (size_t i = 0; i < common; ++i) {
        if (a[i] != b[i]) {
            ++diffBytes;
            if (firstDiff == static_cast<size_t>(-1)) firstDiff = i;
            lastDiff = i;
        }
    }
    o << "Common bytes that differ: " << diffBytes << " out of " << common << "\n";
    if (diffBytes > 0) {
        o << std::hex << std::uppercase << std::setfill('0');
        o << "First diff at file offset 0x" << std::setw(8) << firstDiff << "\n"
          << "Last diff at file offset  0x" << std::setw(8) << lastDiff << "\n";
        o << std::dec;
    }
    if (a.size() > b.size()) {
        o << "Tail (added bytes): " << (a.size() - b.size()) << " bytes after offset "
          << b.size() << " (most of this is the new .injsec section).\n";
    }

    // Show high-level structural diff via the inspector.
    o << "\n=== CURRENT ===\n" << FormatReport(InspectExe(exePath));
    o << "\n=== ORIGINAL ===\n" << FormatReport(InspectExe(backup));
    return o.str();
}

}
