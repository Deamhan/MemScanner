#pragma once

#include <functional>
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

	using MemInfoT = SystemDefinitions::MEMORY_BASIC_INFORMATION_T<PTR_T<arch>>;
	using MemoryMapT = std::map<PTR_T<arch>, MemInfoT>;
	using FlatMemoryMapT = std::vector<MemInfoT>;
	using GroupedMemoryMapT = std::map<PTR_T<arch>, FlatMemoryMapT>;

	static MemoryMapT GetMemoryMap(HANDLE hProcess, const Wow64Helper<arch>& api);

	static FlatMemoryMapT GetFlatMemoryMap(
		const MemoryMapT& mm, const std::function<bool(const MemInfoT&)>& filter);

	static GroupedMemoryMapT GetGroupedMemoryMap(
		const MemoryMapT& mm, const std::function<bool(const MemInfoT&)>& filter);
};


