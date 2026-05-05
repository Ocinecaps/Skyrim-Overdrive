#pragma once

#include <string>

namespace patcher {

enum class LogLevel { Info, Warn, Error };

void InitLog(const std::string& path);
void Log(LogLevel level, const char* fmt, ...);
void CloseLog();

#define LOGI(...) ::patcher::Log(::patcher::LogLevel::Info,  __VA_ARGS__)
#define LOGW(...) ::patcher::Log(::patcher::LogLevel::Warn,  __VA_ARGS__)
#define LOGE(...) ::patcher::Log(::patcher::LogLevel::Error, __VA_ARGS__)

}
