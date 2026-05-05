#include "BytePatches.h"
#include "Logging.h"

#include <windows.h>
#include <vector>
#include <cstdint>
#include <cstring>

namespace patcher {

namespace {

struct BytePatch {
    uint32_t    va;            // virtual address in the unpacked TESV.exe
    const char* desc;
    int         len;
    uint8_t     original[16];
    uint8_t     patched[16];
};

// =============================================================================
// PATCH LIST
// =============================================================================
//
// 2026-05-03 — Patch #1: message-pump idle-loop Sleep(0) → PAUSE PAUSE
//
// Identified at runtime by SleepProfiler in SkyrimRenderOverdrive.dll: the
// hottest Sleep call in TESV.exe by ~7×, called 400,436 times per ~30-second
// gameplay window. Disassembly (sub_691410):
//
//   00691410: cmp byte ptr [ecx+2Ch], 0
//   00691417: jz exit                      ; only enter loop if flag set
//   ...                                    ; load function pointers
//   00691440:  6A 00         push 0        ; dwMilliseconds
//   00691442:  FF D5         call ebp      ; Sleep — 400k+ syscalls per window
//   00691444:  ...           PeekMessage / TranslateMessage / DispatchMessage
//   00691493:  cmp byte ptr [ecx+2Ch], 0
//   0069149B:  jnz 00691440                ; loop while flag still set
//
// This is Skyrim's "wait for something while pumping Win32 messages" pattern.
// Sleep(0) is a kernel transition to NtDelayExecution (~300+ cycles per call,
// pure overhead). PAUSE is a CPU hint instruction (~5 cycles, no syscall).
//
// Stack effect of original:  push 0 (esp -= 4) + call Sleep (Sleep ret 4 → esp += 4) = NET 0
// Stack effect of patch:     pause + pause = NET 0
//
// Risk: thread now busy-waits instead of yielding to OS scheduler. This thread
// can no longer be descheduled at this point; if it's pinned to a core also
// running another important thread (HT sibling), perf there could degrade.
// Mitigation: PAUSE specifically tells the CPU "I'm spin-waiting" and lets HT
// sibling get full pipeline. Should be net-neutral or positive on modern CPUs.
//
// =============================================================================
// 2026-05-03 — RULE LEARNED THE HARD WAY: do not replace Sleep with pure
// PAUSE in a CAS spinlock that has NO OTHER YIELD POINT.
//
// We tried Patch #2 against sub_401710 (recursive mutex acquire). The patch
// was structurally correct (8 bytes in, 8 bytes out, stack-neutral), but it
// caused the game to crash on first contended acquire. Reason:
//
//   loop:
//       push 0
//       call ds:Sleep    ; the ONLY yield point in the whole loop
//       cas retry
//       jnz loop
//
// With Sleep replaced by PAUSE, the spinning thread never gives up the core.
// When the mutex is contended, the thread holding the lock might be
// descheduled — and never gets rescheduled because our thread is hogging
// the core with PAUSE. Livelock → hang → crash.
//
// Patch #1 (message-pump) survived because that loop exits frequently AND
// also calls PeekMessage which has natural yield behavior.
//
// Future Sleep patches must ONLY target loops that have:
//   (a) Another natural yield point (file I/O, message pump, queue wait), OR
//   (b) An exit condition that fires within microseconds (so spinning is
//       bounded), OR
//   (c) A SwitchToThread substitute (not a pure NOP/PAUSE).
//
// SwitchToThread is the right replacement for pure CAS spinlocks. It's still
// __stdcall but takes 0 args (Sleep takes 1) — so a direct IAT-slot swap
// would leave a stack-imbalance. Doing this safely needs a longer splice or
// a small dispatch thunk. Deferred until we have more profiling.
// =============================================================================
BytePatch g_patches[] = {
    {
        0x00691440, "sub_691410 message-pump Sleep(0) -> pause/pause",
        4,
        { 0x6A, 0x00, 0xFF, 0xD5 },                    // push 0; call ebp (Sleep)
        { 0xF3, 0x90, 0xF3, 0x90 },                    // pause; pause
    },
};

// PE helper: open file, parse headers, return base + section table.
struct MappedExe {
    HANDLE hFile  = INVALID_HANDLE_VALUE;
    HANDLE hMap   = nullptr;
    uint8_t* base = nullptr;
    SIZE_T size   = 0;

    ~MappedExe() {
        if (base)  { FlushViewOfFile(base, 0); UnmapViewOfFile(base); }
        if (hMap)  CloseHandle(hMap);
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    }
};

bool MapExe(const std::string& path, MappedExe& out) {
    out.hFile = CreateFileA(path.c_str(),
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr);
    if (out.hFile == INVALID_HANDLE_VALUE) {
        LOGE("BytePatches: cannot open %s (GetLastError=%lu)", path.c_str(), GetLastError());
        return false;
    }
    LARGE_INTEGER sz = {};
    if (!GetFileSizeEx(out.hFile, &sz)) {
        LOGE("BytePatches: GetFileSizeEx failed (GetLastError=%lu)", GetLastError());
        return false;
    }
    out.size = (SIZE_T)sz.QuadPart;
    out.hMap = CreateFileMappingA(out.hFile, nullptr, PAGE_READWRITE, 0, 0, nullptr);
    if (!out.hMap) {
        LOGE("BytePatches: CreateFileMapping failed (GetLastError=%lu)", GetLastError());
        return false;
    }
    out.base = (uint8_t*)MapViewOfFile(out.hMap, FILE_MAP_WRITE, 0, 0, 0);
    if (!out.base) {
        LOGE("BytePatches: MapViewOfFile failed (GetLastError=%lu)", GetLastError());
        return false;
    }
    return true;
}

// VA -> file offset using PE section table.
bool VaToFileOffset(const uint8_t* base, uint32_t va, SIZE_T fileSize, uint32_t& outOff) {
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const uint32_t imageBase = nt->OptionalHeader.ImageBase;
    if (va < imageBase) return false;
    const uint32_t rva = va - imageBase;

    auto sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
            outOff = sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
            if (outOff >= fileSize) return false;
            return true;
        }
    }
    return false;
}

}  // namespace

bool ApplyBytePatches(const std::string& exePath) {
    MappedExe ex;
    if (!MapExe(exePath, ex)) return false;

    int applied = 0;
    int alreadyApplied = 0;
    int unknown = 0;

    for (const auto& p : g_patches) {
        uint32_t off = 0;
        if (!VaToFileOffset(ex.base, p.va, ex.size, off)) {
            LOGE("BytePatches: VA 0x%08X (%s) — could not resolve to file offset",
                 p.va, p.desc);
            ++unknown;
            continue;
        }
        uint8_t* target = ex.base + off;
        if (std::memcmp(target, p.original, p.len) == 0) {
            // Pristine — apply.
            std::memcpy(target, p.patched, p.len);
            LOGI("BytePatches: applied at VA 0x%08X (file off 0x%08X) — %s",
                 p.va, off, p.desc);
            ++applied;
        } else if (std::memcmp(target, p.patched, p.len) == 0) {
            LOGI("BytePatches: ALREADY APPLIED at VA 0x%08X — %s",
                 p.va, p.desc);
            ++alreadyApplied;
        } else {
            // Bytes don't match either pattern — abort this patch.
            char hex[64] = {};
            int hp = 0;
            for (int i = 0; i < p.len && hp + 3 < (int)sizeof(hex); ++i) {
                hp += std::snprintf(hex + hp, sizeof(hex) - hp, "%02X ", target[i]);
            }
            LOGE("BytePatches: VA 0x%08X — UNKNOWN BYTES at site (%s). "
                 "Found: %s — refusing to patch.",
                 p.va, p.desc, hex);
            ++unknown;
        }
    }
    LOGI("BytePatches: %d applied, %d already applied, %d unknown / %zu total",
         applied, alreadyApplied, unknown, sizeof(g_patches) / sizeof(g_patches[0]));
    return unknown == 0;
}

bool RevertBytePatches(const std::string& exePath) {
    MappedExe ex;
    if (!MapExe(exePath, ex)) return false;
    int reverted = 0;
    for (const auto& p : g_patches) {
        uint32_t off = 0;
        if (!VaToFileOffset(ex.base, p.va, ex.size, off)) continue;
        uint8_t* target = ex.base + off;
        if (std::memcmp(target, p.patched, p.len) == 0) {
            std::memcpy(target, p.original, p.len);
            LOGI("BytePatches: reverted at VA 0x%08X — %s", p.va, p.desc);
            ++reverted;
        }
    }
    LOGI("BytePatches: %d reverted", reverted);
    return true;
}

}
