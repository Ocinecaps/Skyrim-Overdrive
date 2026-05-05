#pragma once

#include <string>

namespace overdrive {

void InitLogger(const std::string& path);
void Logf(const char* fmt, ...);
void CloseLogger();

#define OD_LOG(...) ::overdrive::Logf(__VA_ARGS__)

}
