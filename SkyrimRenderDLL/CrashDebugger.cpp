#include "CrashDebugger.h"
#include "DebugLogger.h"

#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <shlwapi.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <algorithm>

namespace overdrive::crashdbg {

namespace {

// =============================================================================
// TESV symbol table — built from IDA extraction folder at startup
// =============================================================================
//
// We have NO PDB for TESV.exe. The user's IDA extractions encode function VAs
// in filenames (`xrefs_API_NNN_0xVVVVVVVV.txt`) and subfolder names
// (`sub_NNNNNN`). We scan those once, dedup, sort, then do binary search to
// resolve any VA in TESV.exe's range to "sub_NNNNNN+0xOFFSET".
//
// Each entry is just a uint32 VA — the name is reconstructed on demand as
// "sub_NNNNNN" by formatting the VA. Saves memory; we have potentially tens
// of thousands of entries.
const char* kIdaExtractionRoot = "C:\\Users\\nro\\Documents\\ida scripts and extracted";

std::vector<uint32_t>* g_tesvFnAddrs = nullptr;  // sorted ascending
uint32_t g_tesvBase = 0;
uint32_t g_tesvEnd  = 0;
LPTOP_LEVEL_EXCEPTION_FILTER g_prevFilter = nullptr;
std::atomic<bool> g_installed{false};
std::atomic<bool> g_inHandler{false};   // re-entry guard
char g_crashLogPath[MAX_PATH] = {};

// =============================================================================
// IDA-extraction folder scanner
// =============================================================================
//
// Recurse the user's extraction folder, look at every directory entry name,
// extract any `0xVVVVVVVV` substring that fits in a uint32. Also catch
// `sub_NNNNNN` folder names. Dedup at the end.
//
// Cost: enumerates a few thousand folders + tens of thousands of files.
// ~500ms to 2s on a warm cache. Done once at startup on the worker thread
// so it doesn't block DllMain.

bool ParseHexU32(const char* s, uint32_t& out) {
    // Accept exactly 8 hex digits. Handles both 0xVVVVVVVV (skip 0x) and
    // bare 8-digit hex.
    if (!s) return false;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    int seen = 0;
    uint32_t v = 0;
    while (seen < 8 && s[seen]) {
        char c = s[seen];
        uint32_t d;
        if (c >= '0' && c <= '9') d = (uint32_t)(c - '0');
        else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A' + 10);
        else if (c >= 'a' && c <= 'f') d = (uint32_t)(c - 'a' + 10);
        else break;
        v = (v << 4) | d;
        ++seen;
    }
    if (seen < 6) return false;  // require at least 6 hex digits to be plausible
    out = v;
    return true;
}

// Try to extract any 0xVVVVVVVV embedded in the name. Returns true if found.
bool ExtractAddrFromName(const char* name, uint32_t& outAddr) {
    // Find "0x" or "0X" or "sub_" anywhere.
    for (const char* p = name; *p; ++p) {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
            if (ParseHexU32(p, outAddr)) return true;
        }
        if (p[0] == 's' && p[1] == 'u' && p[2] == 'b' && p[3] == '_') {
            if (ParseHexU32(p + 4, outAddr)) return true;
        }
    }
    return false;
}

void ScanDir(const char* path, std::vector<uint32_t>& addrs, int depth) {
    if (depth > 6) return;  // safety
    char pattern[MAX_PATH];
    std::snprintf(pattern, sizeof(pattern), "%s\\*", path);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == '.' &&
            (fd.cFileName[1] == 0 ||
             (fd.cFileName[1] == '.' && fd.cFileName[2] == 0))) {
            continue;  // skip . and ..
        }
        uint32_t a = 0;
        if (ExtractAddrFromName(fd.cFileName, a)) {
            addrs.push_back(a);
        }
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            char sub[MAX_PATH];
            std::snprintf(sub, sizeof(sub), "%s\\%s", path, fd.cFileName);
            ScanDir(sub, addrs, depth + 1);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

void BuildTesvSymbolTable() {
    if (g_tesvFnAddrs) return;
    g_tesvFnAddrs = new std::vector<uint32_t>();
    g_tesvFnAddrs->reserve(50000);

    DWORD t0 = GetTickCount();
    ScanDir(kIdaExtractionRoot, *g_tesvFnAddrs, 0);

    // Dedup + sort.
    std::sort(g_tesvFnAddrs->begin(), g_tesvFnAddrs->end());
    auto last = std::unique(g_tesvFnAddrs->begin(), g_tesvFnAddrs->end());
    g_tesvFnAddrs->erase(last, g_tesvFnAddrs->end());

    // Filter: keep only addrs in TESV.exe range.
    if (g_tesvBase != 0 && g_tesvEnd != 0) {
        auto end = std::remove_if(g_tesvFnAddrs->begin(), g_tesvFnAddrs->end(),
            [](uint32_t a) { return a < g_tesvBase || a >= g_tesvEnd; });
        g_tesvFnAddrs->erase(end, g_tesvFnAddrs->end());
    }

    DWORD elapsed = GetTickCount() - t0;
    OD_LOG("[CrashDbg] TESV symbol table built: %zu unique function VAs from IDA extractions (%lums)",
           g_tesvFnAddrs->size(), elapsed);
}

// =============================================================================
// Symbol lookup
// =============================================================================

const char* ResolveTesvImpl(uint32_t va, uint32_t* outOffset) {
    static thread_local char buf[64];
    if (!g_tesvFnAddrs || g_tesvFnAddrs->empty() ||
        va < g_tesvBase || va >= g_tesvEnd) {
        std::snprintf(buf, sizeof(buf), "?");
        if (outOffset) *outOffset = 0;
        return buf;
    }
    // Find largest entry <= va.
    auto it = std::upper_bound(g_tesvFnAddrs->begin(), g_tesvFnAddrs->end(), va);
    if (it == g_tesvFnAddrs->begin()) {
        std::snprintf(buf, sizeof(buf), "?");
        if (outOffset) *outOffset = 0;
        return buf;
    }
    --it;
    uint32_t start = *it;
    if (outOffset) *outOffset = va - start;
    std::snprintf(buf, sizeof(buf), "sub_%X", start);
    return buf;
}

// dbghelp lookup — used for resolving non-TESV addresses (Windows DLLs).
// Returns true if it resolved.
bool ResolveDbghelp(uint32_t va, char* out, size_t outSize) {
    char buf[sizeof(SYMBOL_INFO) + 256] = {};
    auto* sym = reinterpret_cast<SYMBOL_INFO*>(buf);
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen   = 255;
    DWORD64 disp = 0;
    if (SymFromAddr(GetCurrentProcess(), (DWORD64)va, &disp, sym)) {
        std::snprintf(out, outSize, "%s+0x%llX", sym->Name, (unsigned long long)disp);
        return true;
    }
    return false;
}

const char* ModuleNameFor(uint32_t va) {
    static thread_local char nameBuf[64];
    HMODULE mods[256];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        nameBuf[0] = 0; return nameBuf;
    }
    int n = (int)(needed / sizeof(HMODULE));
    if (n > 256) n = 256;
    for (int i = 0; i < n; ++i) {
        MODULEINFO mi = {};
        if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) continue;
        uintptr_t base = (uintptr_t)mi.lpBaseOfDll;
        if (va >= base && va < base + mi.SizeOfImage) {
            char path[MAX_PATH] = {};
            GetModuleFileNameExA(GetCurrentProcess(), mods[i], path, MAX_PATH);
            const char* slash = std::strrchr(path, '\\');
            std::snprintf(nameBuf, sizeof(nameBuf), "%s", slash ? slash + 1 : path);
            return nameBuf;
        }
    }
    nameBuf[0] = '?'; nameBuf[1] = 0;
    return nameBuf;
}

// =============================================================================
// Crash log writer
// =============================================================================

void WriteCrashLine(HANDLE h, const char* line) {
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, line, (DWORD)std::strlen(line), &written, nullptr);
    static const char nl[] = "\r\n";
    WriteFile(h, nl, 2, &written, nullptr);
}

void WriteCrashLineF(HANDLE h, const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = 0;
    WriteCrashLine(h, buf);
}

const char* ExceptionCodeName(DWORD code) {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:         return "ACCESS_VIOLATION";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_DATATYPE_MISALIGNMENT:    return "DATATYPE_MISALIGNMENT";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_FLT_INVALID_OPERATION:    return "FLT_INVALID_OPERATION";
        case EXCEPTION_FLT_OVERFLOW:             return "FLT_OVERFLOW";
        case EXCEPTION_ILLEGAL_INSTRUCTION:      return "ILLEGAL_INSTRUCTION";
        case EXCEPTION_IN_PAGE_ERROR:            return "IN_PAGE_ERROR";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "INT_DIVIDE_BY_ZERO";
        case EXCEPTION_INT_OVERFLOW:             return "INT_OVERFLOW";
        case EXCEPTION_PRIV_INSTRUCTION:         return "PRIV_INSTRUCTION";
        case EXCEPTION_STACK_OVERFLOW:           return "STACK_OVERFLOW";
        case EXCEPTION_BREAKPOINT:               return "BREAKPOINT";
        case EXCEPTION_SINGLE_STEP:              return "SINGLE_STEP";
        case 0xE06D7363:                         return "MS_C++_EH";
        default:                                 return "(unknown)";
    }
}

LONG WINAPI OurFilter(EXCEPTION_POINTERS* info) {
    // Re-entry guard: if our crash handler itself crashes, don't recurse.
    bool expected = false;
    if (!g_inHandler.compare_exchange_strong(expected, true)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    HANDLE h = CreateFileA(g_crashLogPath, GENERIC_WRITE, FILE_SHARE_READ,
                           nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        g_inHandler.store(false);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    SetFilePointer(h, 0, nullptr, FILE_END);

    SYSTEMTIME t;
    GetLocalTime(&t);
    WriteCrashLine(h, "================================================================");
    WriteCrashLineF(h, "[CRASH] %04u-%02u-%02u %02u:%02u:%02u.%03u  pid=%lu  tid=%lu",
                    t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds,
                    GetCurrentProcessId(), GetCurrentThreadId());

    EXCEPTION_RECORD* er = info->ExceptionRecord;
    CONTEXT* ctx         = info->ContextRecord;

    WriteCrashLineF(h, "  code=0x%08X (%s)  flags=0x%08X  addr=0x%08X",
                    er->ExceptionCode, ExceptionCodeName(er->ExceptionCode),
                    er->ExceptionFlags, (unsigned)(uintptr_t)er->ExceptionAddress);
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2) {
        const char* op = (er->ExceptionInformation[0] == 0) ? "READ"
                       : (er->ExceptionInformation[0] == 1) ? "WRITE"
                       : (er->ExceptionInformation[0] == 8) ? "EXECUTE-DEP"
                       : "?";
        WriteCrashLineF(h, "  AV: %s at 0x%08X",
                        op, (unsigned)er->ExceptionInformation[1]);
    }

    WriteCrashLineF(h, "  EIP=%08X EBP=%08X ESP=%08X EFL=%08X",
                    ctx->Eip, ctx->Ebp, ctx->Esp, ctx->EFlags);
    WriteCrashLineF(h, "  EAX=%08X EBX=%08X ECX=%08X EDX=%08X ESI=%08X EDI=%08X",
                    ctx->Eax, ctx->Ebx, ctx->Ecx, ctx->Edx, ctx->Esi, ctx->Edi);

    // Resolve crash EIP first.
    {
        char sym[256];
        const char* mod = ModuleNameFor(ctx->Eip);
        if (((uint32_t)ctx->Eip >= g_tesvBase) && ((uint32_t)ctx->Eip < g_tesvEnd)) {
            uint32_t off = 0;
            const char* tname = ResolveTesvImpl((uint32_t)ctx->Eip, &off);
            std::snprintf(sym, sizeof(sym), "%s+0x%X", tname, off);
        } else if (!ResolveDbghelp((uint32_t)ctx->Eip, sym, sizeof(sym))) {
            std::snprintf(sym, sizeof(sym), "(no sym)");
        }
        WriteCrashLineF(h, "  CRASH SITE:  [%s]  %s", mod, sym);
    }

    WriteCrashLine(h, "  STACK (StackWalk64, max 32 frames):");

    STACKFRAME64 frame = {};
    frame.AddrPC.Mode    = AddrModeFlat;
    frame.AddrPC.Offset  = ctx->Eip;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = ctx->Ebp;
    frame.AddrStack.Mode = AddrModeFlat;
    frame.AddrStack.Offset = ctx->Esp;

    CONTEXT walkCtx = *ctx;
    for (int i = 0; i < 32; ++i) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_I386,
                         GetCurrentProcess(), GetCurrentThread(),
                         &frame, &walkCtx,
                         nullptr,
                         SymFunctionTableAccess64, SymGetModuleBase64,
                         nullptr)) {
            break;
        }
        DWORD64 pc = frame.AddrPC.Offset;
        if (pc == 0) break;

        char sym[256];
        const char* mod = ModuleNameFor((uint32_t)pc);
        if (((uint32_t)pc >= g_tesvBase) && ((uint32_t)pc < g_tesvEnd)) {
            uint32_t off = 0;
            const char* tname = ResolveTesvImpl((uint32_t)pc, &off);
            std::snprintf(sym, sizeof(sym), "%s+0x%X", tname, off);
        } else if (!ResolveDbghelp((uint32_t)pc, sym, sizeof(sym))) {
            std::snprintf(sym, sizeof(sym), "(no sym)");
        }

        WriteCrashLineF(h, "    #%-2d  0x%08X  [%s]  %s",
                        i, (unsigned)pc, mod, sym);
    }

    WriteCrashLine(h, "");
    CloseHandle(h);

    g_inHandler.store(false);
    // EXCEPTION_CONTINUE_SEARCH lets WER / OS take over after we've logged.
    // Use EXCEPTION_EXECUTE_HANDLER if we'd rather exit silently.
    return EXCEPTION_CONTINUE_SEARCH;
}

void EnsureSymInit() {
    static bool inited = false;
    if (inited) return;
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES |
                  SYMOPT_UNDNAME | SYMOPT_FAIL_CRITICAL_ERRORS);
    const char* symPath =
        "srv*C:\\Users\\nro\\AppData\\Local\\Symbols*"
        "https://msdl.microsoft.com/download/symbols";
    SymInitialize(GetCurrentProcess(), symPath, TRUE);
    inited = true;
}

void CaptureTesvRange() {
    HMODULE m = GetModuleHandleW(nullptr);
    if (!m) return;
    MODULEINFO mi = {};
    if (GetModuleInformation(GetCurrentProcess(), m, &mi, sizeof(mi))) {
        g_tesvBase = (uint32_t)(uintptr_t)mi.lpBaseOfDll;
        g_tesvEnd  = g_tesvBase + mi.SizeOfImage;
    }
    if (g_tesvBase == 0) { g_tesvBase = 0x00400000; g_tesvEnd = 0x02000000; }
}

void BuildCrashLogPath() {
    HMODULE m = GetModuleHandleW(nullptr);
    char dir[MAX_PATH] = {};
    GetModuleFileNameA(m, dir, MAX_PATH);
    PathRemoveFileSpecA(dir);
    std::snprintf(g_crashLogPath, sizeof(g_crashLogPath),
                  "%s\\skyrim_overdrive_crash.log", dir);
}

}  // namespace

bool Install() {
    if (g_installed.load()) return true;

    CaptureTesvRange();
    BuildCrashLogPath();
    EnsureSymInit();
    BuildTesvSymbolTable();

    g_prevFilter = SetUnhandledExceptionFilter(OurFilter);
    g_installed.store(true);

    OD_LOG("[CrashDbg] Installed. TESV range=0x%08X..0x%08X. Crash log: %s",
           g_tesvBase, g_tesvEnd, g_crashLogPath);
    return true;
}

void Shutdown() {
    if (!g_installed.load()) return;
    SetUnhandledExceptionFilter(g_prevFilter);
    g_installed.store(false);
}

const char* ResolveTesvAddr(unsigned long va, unsigned long* outOffset) {
    uint32_t off = 0;
    const char* r = ResolveTesvImpl((uint32_t)va, &off);
    if (outOffset) *outOffset = off;
    return r;
}

bool IsTesvCodeAddr(unsigned long va, unsigned long withinBytes) {
    if (!g_tesvFnAddrs || g_tesvFnAddrs->empty()) return false;
    if (va < g_tesvBase || va >= g_tesvEnd) return false;
    auto it = std::upper_bound(g_tesvFnAddrs->begin(), g_tesvFnAddrs->end(),
                               (uint32_t)va);
    if (it == g_tesvFnAddrs->begin()) return false;
    --it;
    uint32_t offset = (uint32_t)va - *it;
    return offset <= withinBytes;
}

}
