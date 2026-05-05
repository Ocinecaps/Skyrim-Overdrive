#include "DebugLogger.h"

#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <mutex>

namespace overdrive {

namespace {
FILE* g_log = nullptr;
std::mutex g_mu;
constexpr long kMaxLogBytes = 1 * 1024 * 1024;
}

void InitLogger(const std::string& path) {
    std::lock_guard<std::mutex> lk(g_mu);
    // Truncate if existing log is over the cap; otherwise append.
    bool truncate = false;
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER sz{};
        if (GetFileSizeEx(h, &sz) && sz.QuadPart > kMaxLogBytes) {
            truncate = true;
        }
        CloseHandle(h);
    }
    fopen_s(&g_log, path.c_str(), truncate ? "w" : "a");
    if (g_log) {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        fprintf(g_log, "=== SkyrimRenderOverdrive session start %04d-%02d-%02d %02d:%02d:%02d pid=%lu ===\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            GetCurrentProcessId());
        fflush(g_log);
    }
}

void Logf(const char* fmt, ...) {
    char body[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(body, sizeof(body), fmt, args);
    va_end(args);

    SYSTEMTIME st{};
    GetLocalTime(&st);
    char line[2200];
    snprintf(line, sizeof(line), "[%02d:%02d:%02d.%03d][tid=%lu] %s\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        GetCurrentThreadId(), body);

    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (g_log) {
            fputs(line, g_log);
            fflush(g_log);
        }
    }
    OutputDebugStringA(line);
}

void CloseLogger() {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_log) {
        fclose(g_log);
        g_log = nullptr;
    }
}

}
