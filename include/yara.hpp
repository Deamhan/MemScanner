#pragma once

#include <list>
#include <string>

#include "memhelper.hpp"

void ScanUsingYara(HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region, std::list<std::string>& result);
void SetYaraRules(const std::list<std::string>& rules);
