#pragma once

#include "ntdll64.h"

int ScanMemory(uint32_t sensitivity = 0, uint32_t pid = 0, const wchar_t* dumpDir = nullptr);
