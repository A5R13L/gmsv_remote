#pragma once
#include "../includes.h"

namespace Remote::Logger
{
void Log(const char *Format, ...);
void Log(const std::string Message, ...);

std::string Info(const char *Format);
std::string Success(const char *Format);
std::string Error(const char *Format);
std::string Warning(const char *Format);
} // namespace Remote::Logger
