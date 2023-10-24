#pragma once

#include <map>
#include <vector>

#include "ntdll64.hpp"
#include "system_defs.hpp"

template <CPUArchitecture arch>
class MemoryHelper
{
public:
	static void CloseHandleByPtr(HANDLE* handle);
	static bool EnableDebugPrivilege();

	static const uint32_t PAGE_SIZE = 4096;

	using MemoryMap_t = std::map<PTR_T<arch>, SystemDefinitions::MEMORY_BASIC_INFORMATION_T<PTR_T<arch>>>;

	static MemoryMap_t GetMemoryMap(HANDLE hProcess, const Wow64Helper<arch>& api);
	static std::vector<SystemDefinitions::MEMORY_BASIC_INFORMATION_T<PTR_T<arch>>> GetFlatMemoryMap(const MemoryMap_t& mm);
};


