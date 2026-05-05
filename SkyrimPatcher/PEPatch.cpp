#include "PEPatch.h"
#include "Logging.h"

#include <windows.h>
#include <fstream>
#include <vector>
#include <cstring>

namespace patcher {

namespace {

constexpr DWORD kInjsecSize        = 0x3000;
constexpr DWORD kOff_TLSDirectory  = 0x000;  // IMAGE_TLS_DIRECTORY32 (24 bytes)
constexpr DWORD kOff_TLSIndexSlot  = 0x040;  // 4-byte slot loader writes index into
constexpr DWORD kOff_CallbackArray = 0x080;  // [existing N callbacks..., ours, NULL]
constexpr DWORD kOff_CallbackCode  = 0x200;  // x86 stub entry (room for ~96 callbacks above)
constexpr DWORD kOff_DllNameString = 0x500;  // ASCII zero-terminated DLL name

constexpr DWORD kMaxExistingCallbacks = 64;  // sanity cap when walking source array

inline DWORD AlignUp(DWORD v, DWORD a) {
    return (v + a - 1) & ~(a - 1);
}

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

DWORD ResolveLoadLibraryA() {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) return 0;
    return reinterpret_cast<DWORD>(GetProcAddress(k32, "LoadLibraryA"));
}

DWORD RvaToFileOffset(DWORD rva, const std::vector<IMAGE_SECTION_HEADER>& sections) {
    for (const auto& sec : sections) {
        const DWORD vSize = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
        if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + vSize) {
            return sec.PointerToRawData + (rva - sec.VirtualAddress);
        }
    }
    return 0;
}

// Reads NULL-terminated array of DWORD callback VAs from the file.
std::vector<DWORD> ReadExistingCallbackArray(std::fstream& file,
                                             DWORD callbackArrayVA,
                                             DWORD imageBase,
                                             const std::vector<IMAGE_SECTION_HEADER>& sections) {
    std::vector<DWORD> result;
    if (callbackArrayVA == 0) return result;

    const DWORD rva = callbackArrayVA - imageBase;
    const DWORD off = RvaToFileOffset(rva, sections);
    if (off == 0) {
        LOGW("Existing TLS callback array VA 0x%08X has no file mapping; skipping merge.",
             callbackArrayVA);
        return result;
    }

    file.clear();
    file.seekg(off, std::ios::beg);
    for (DWORD i = 0; i < kMaxExistingCallbacks; ++i) {
        DWORD ptr = 0;
        file.read(reinterpret_cast<char*>(&ptr), sizeof(ptr));
        if (!file || ptr == 0) break;
        result.push_back(ptr);
    }
    return result;
}

// Build the x86 TLS callback stub.
// Signature: void NTAPI Cb(PVOID DllHandle, DWORD Reason, PVOID Reserved)
//
// Calls LoadLibraryA("SkyrimRenderOverdrive.dll") on EVERY callback invocation
// (PROCESS_ATTACH, THREAD_ATTACH, THREAD_DETACH, PROCESS_DETACH). This is safe
// because LoadLibraryA refcounts — repeated calls on an already-loaded DLL
// just bump the refcount and return. This matches DoW's proven stub.
//
// History note: an earlier version of this stub tried to gate on Reason==1,
// but the stack-offset arithmetic was wrong: after pushad+pushfd, Reason is at
// [esp+0x2C], not [esp+0x28]. The cmp was reading DllHandle (always non-zero)
// against 1, so LoadLibraryA was never actually called. Removing the check
// entirely is simpler and avoids that class of bug.
//
//   60                       pushad
//   68 <imm32 dllStrVA>      push offset DllName
//   B8 <imm32 LoadLibraryA>  mov  eax, LoadLibraryA
//   FF D0                    call eax
//   61                       popad
//   C2 0C 00                 ret 0Ch          ; stdcall, callee cleans 3 args
std::vector<BYTE> BuildStub(DWORD dllStrVA, DWORD loadLibraryAVA) {
    std::vector<BYTE> code;
    auto B = [&](BYTE b) { code.push_back(b); };
    auto D = [&](DWORD d) {
        BYTE bytes[4];
        memcpy(bytes, &d, 4);
        code.insert(code.end(), bytes, bytes + 4);
    };

    B(0x60);                                      // pushad
    B(0x68); D(dllStrVA);                         // push imm32 dllStrVA
    B(0xB8); D(loadLibraryAVA);                   // mov  eax, imm32 LoadLibraryA
    B(0xFF); B(0xD0);                             // call eax
    B(0x61);                                      // popad
    B(0xC2); B(0x0C); B(0x00);                    // ret  0Ch (stdcall)
    return code;
}

} // namespace

bool AddInjsecAndTLS(const std::string& exePath, const std::string& dllNameToLoad) {
    std::fstream file(exePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        LOGE("PEPatch: cannot open %s", exePath.c_str());
        return false;
    }

    IMAGE_DOS_HEADER dos{};
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!file || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        LOGE("PEPatch: bad DOS signature");
        return false;
    }

    file.seekg(dos.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS32 nt{};
    file.read(reinterpret_cast<char*>(&nt), sizeof(nt));
    if (!file ||
        nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        LOGE("PEPatch: not a PE32 image");
        return false;
    }

    if (nt.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        LOGE("PEPatch: image has DYNAMIC_BASE flag — absolute VAs in the TLS stub "
             "would be invalidated by ASLR. Aborting to avoid silent corruption.");
        return false;
    }

    nt.FileHeader.Characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE;

    const WORD secCount = nt.FileHeader.NumberOfSections;
    std::vector<IMAGE_SECTION_HEADER> sections(secCount);
    file.read(reinterpret_cast<char*>(sections.data()),
              static_cast<std::streamsize>(secCount) * sizeof(IMAGE_SECTION_HEADER));
    if (!file) {
        LOGE("PEPatch: failed to read section headers");
        return false;
    }

    // Detect and read any existing TLS directory so we can merge with it
    // instead of clobbering Skyrim's own TLS callbacks.
    const DWORD existingTlsRVA  = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    const DWORD existingTlsSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;

    ImageTlsDirectory32 existingTls{};
    std::vector<DWORD>  existingCallbacks;

    if (existingTlsRVA != 0 && existingTlsSize >= sizeof(ImageTlsDirectory32)) {
        const DWORD off = RvaToFileOffset(existingTlsRVA, sections);
        if (off == 0) {
            LOGE("PEPatch: existing TLS dir RVA 0x%08X has no file mapping", existingTlsRVA);
            return false;
        }
        file.clear();
        file.seekg(off, std::ios::beg);
        file.read(reinterpret_cast<char*>(&existingTls), sizeof(existingTls));
        if (!file) {
            LOGE("PEPatch: failed to read existing TLS directory");
            return false;
        }
        LOGI("Existing TLS dir found at RVA=0x%08X: callbacks VA=0x%08X, indexVA=0x%08X, "
             "rawStart=0x%08X, rawEnd=0x%08X, zeroFill=%lu",
             existingTlsRVA, existingTls.AddressOfCallBacks, existingTls.AddressOfIndex,
             existingTls.StartAddressOfRawData, existingTls.EndAddressOfRawData,
             existingTls.SizeOfZeroFill);

        existingCallbacks = ReadExistingCallbackArray(
            file, existingTls.AddressOfCallBacks, nt.OptionalHeader.ImageBase, sections);
        LOGI("Existing TLS callback array has %zu entries — will preserve them all.",
             existingCallbacks.size());

        if (existingCallbacks.size() + 2 > (kOff_CallbackCode - kOff_CallbackArray) / 4) {
            LOGE("PEPatch: existing callback list too large to merge (%zu entries)",
                 existingCallbacks.size());
            return false;
        }
    } else if (existingTlsRVA != 0 || existingTlsSize != 0) {
        LOGW("PEPatch: existing TLS data dir is non-zero but undersized "
             "(RVA=0x%08X, Size=%lu) — treating as empty.",
             existingTlsRVA, existingTlsSize);
    }

    const DWORD fAlign = nt.OptionalHeader.FileAlignment;
    const DWORD sAlign = nt.OptionalHeader.SectionAlignment;
    const IMAGE_SECTION_HEADER& last = sections.back();

    IMAGE_SECTION_HEADER newSec{};
    memcpy(newSec.Name, ".injsec", 7);
    newSec.VirtualAddress    = AlignUp(last.VirtualAddress + last.Misc.VirtualSize, sAlign);
    newSec.PointerToRawData  = AlignUp(last.PointerToRawData + last.SizeOfRawData, fAlign);
    newSec.Misc.VirtualSize  = kInjsecSize;
    newSec.SizeOfRawData     = AlignUp(kInjsecSize, fAlign);
    newSec.Characteristics   = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
                             | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA;

    nt.FileHeader.NumberOfSections = static_cast<WORD>(secCount + 1);
    nt.OptionalHeader.SizeOfImage  = newSec.VirtualAddress + AlignUp(kInjsecSize, sAlign);

    const DWORD imageBase     = nt.OptionalHeader.ImageBase;
    const DWORD injsecRaw     = newSec.PointerToRawData;
    const DWORD injsecRVA     = newSec.VirtualAddress;
    const DWORD tlsDirRVA     = injsecRVA + kOff_TLSDirectory;
    const DWORD tlsIndexVA    = imageBase + injsecRVA + kOff_TLSIndexSlot;
    const DWORD cbArrayVA     = imageBase + injsecRVA + kOff_CallbackArray;
    const DWORD callbackVA    = imageBase + injsecRVA + kOff_CallbackCode;
    const DWORD dllStringVA   = imageBase + injsecRVA + kOff_DllNameString;

    const DWORD loadLibraryA  = ResolveLoadLibraryA();
    if (loadLibraryA == 0) {
        LOGE("PEPatch: failed to resolve kernel32!LoadLibraryA");
        return false;
    }

    LOGI("Adding .injsec at RVA=0x%08X (raw=0x%08X), SizeOfImage=0x%08X",
         injsecRVA, injsecRaw, nt.OptionalHeader.SizeOfImage);
    LOGI("New TLS dir VA=0x%08X, callbacks VA=0x%08X, stub VA=0x%08X, dllNameVA=0x%08X",
         imageBase + tlsDirRVA, cbArrayVA, callbackVA, dllStringVA);
    LOGI("LoadLibraryA = 0x%08X (this-boot only; re-run patcher after reboot)", loadLibraryA);

    // Repoint TLS data directory at our new TLS dir in .injsec.
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = tlsDirRVA;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size           = sizeof(ImageTlsDirectory32);

    file.clear();
    file.seekp(dos.e_lfanew, std::ios::beg);
    file.write(reinterpret_cast<const char*>(&nt), sizeof(nt));
    file.write(reinterpret_cast<const char*>(sections.data()),
               static_cast<std::streamsize>(secCount) * sizeof(IMAGE_SECTION_HEADER));
    file.write(reinterpret_cast<const char*>(&newSec), sizeof(newSec));

    std::vector<char> blank(newSec.SizeOfRawData, 0);
    file.seekp(injsecRaw, std::ios::beg);
    file.write(blank.data(), static_cast<std::streamsize>(blank.size()));

    // DLL name string.
    if (dllNameToLoad.size() + 1 > (kInjsecSize - kOff_DllNameString)) {
        LOGE("PEPatch: dll name too long for reserved string slot");
        return false;
    }
    file.seekp(injsecRaw + kOff_DllNameString, std::ios::beg);
    file.write(dllNameToLoad.c_str(), static_cast<std::streamsize>(dllNameToLoad.size() + 1));

    // x86 TLS callback stub.
    const std::vector<BYTE> stub = BuildStub(dllStringVA, loadLibraryA);
    file.seekp(injsecRaw + kOff_CallbackCode, std::ios::beg);
    file.write(reinterpret_cast<const char*>(stub.data()),
               static_cast<std::streamsize>(stub.size()));

    // Combined callback array: [existing callbacks..., our stub, NULL]
    file.seekp(injsecRaw + kOff_CallbackArray, std::ios::beg);
    for (DWORD cb : existingCallbacks) {
        file.write(reinterpret_cast<const char*>(&cb), sizeof(cb));
    }
    DWORD ourEntry   = callbackVA;
    DWORD terminator = 0;
    file.write(reinterpret_cast<const char*>(&ourEntry),   sizeof(ourEntry));
    file.write(reinterpret_cast<const char*>(&terminator), sizeof(terminator));

    // New TLS directory in .injsec — preserves Skyrim's StartAddressOfRawData,
    // EndAddressOfRawData, AddressOfIndex, SizeOfZeroFill, Characteristics so
    // the loader still allocates Skyrim's TLS storage correctly. Only the
    // AddressOfCallBacks pointer changes, plus AddressOfIndex if it was 0.
    ImageTlsDirectory32 newTls = existingTls;
    newTls.AddressOfCallBacks = cbArrayVA;
    if (newTls.AddressOfIndex == 0) {
        newTls.AddressOfIndex = tlsIndexVA;
    }
    file.seekp(injsecRaw + kOff_TLSDirectory, std::ios::beg);
    file.write(reinterpret_cast<const char*>(&newTls), sizeof(newTls));

    file.close();
    LOGI("PEPatch: .injsec installed, dll=%s, %zu existing callback(s) preserved",
         dllNameToLoad.c_str(), existingCallbacks.size());
    return true;
}

bool ZeroChecksumAndTimestamp(const std::string& exePath) {
    std::fstream file(exePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        LOGE("ZeroChecksumAndTimestamp: cannot open %s", exePath.c_str());
        return false;
    }
    IMAGE_DOS_HEADER dos{};
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!file || dos.e_magic != IMAGE_DOS_SIGNATURE) return false;

    file.seekg(dos.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS32 nt{};
    file.read(reinterpret_cast<char*>(&nt), sizeof(nt));
    if (!file || nt.Signature != IMAGE_NT_SIGNATURE) return false;

    nt.FileHeader.TimeDateStamp = 0;
    nt.OptionalHeader.CheckSum  = 0;

    file.clear();
    file.seekp(dos.e_lfanew, std::ios::beg);
    file.write(reinterpret_cast<const char*>(&nt), sizeof(nt));
    file.close();
    LOGI("Cleared TimeDateStamp and CheckSum");
    return true;
}

}
