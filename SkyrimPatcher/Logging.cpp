#include "Logging.h"

#include <windows.h>
#include <cstdarg>
#include <cstdio>

namespace patcher {

static FILE* g_log = nullptr;

static const char* LevelStr(LogLevel l) {
    switch (l) {
        case LogLevel::Info:  return "INFO";
        case LogLevel::Warn:  return "WARN";
        case LogLevel::Error: return "ERR ";
    }
    return "?   ";
}

void InitLog(const std::string& path) {
    fopen_s(&g_log, path.c_str(), "w");
    if (g_log) {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        fprintf(g_log, "=== SkyrimPatcher started %04d-%02d-%02d %02d:%02d:%02d ===\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        fflush(g_log);
    }
}

void Log(LogLevel level, const char* fmt, ...) {
    SYSTEMTIME st{};
    GetLocalTime(&st);

    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    char line[2200];
    snprintf(line, sizeof(line), "[%02d:%02d:%02d.%03d][%s] %s\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, LevelStr(level), buf);

    if (g_log) {
        fputs(line, g_log);
        fflush(g_log);
    }
    fputs(line, stdout);
    OutputDebugStringA(line);
}

void CloseLog() {
    if (g_log) {
        fclose(g_log);
        g_log = nullptr;
    }
}

}
