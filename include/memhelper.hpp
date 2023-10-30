#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "ntdll64.hpp"
#include "system_defs.hpp"

class MemoryHelperBase
{
public:
	static void CloseHandleByPtr(HANDLE* handle);
	static bool EnableDebugPrivilege();

	static const uint32_t PAGE_SIZE = 4096;

	enum MemoryAttributes
	{
		RFlag = 1,
		WFlag = 2,
		XFlag = 4,
	};

	static uint32_t protToFlags(uint32_t prot);
};

template <CPUArchitecture arch>
class MemoryHelper : public MemoryHelperBase
{
public:
	using MemInfoT = SystemDefinitions::MEMORY_BASIC_INFORMATION_T<PTR_T<arch>>;
	using MemoryMapT = std::map<PTR_T<arch>, MemInfoT>;
	using FlatMemoryMapT = std::vector<MemInfoT>;
	using GroupedMemoryMapT = std::map<PTR_T<arch>, FlatMemoryMapT>;

	static MemoryMapT GetMemoryMap(HANDLE hProcess, const Wow64Helper<arch>& api);

	static FlatMemoryMapT GetFlatMemoryMap(
		const MemoryMapT& mm, const std::function<bool(const MemInfoT&)>& filter);

	static GroupedMemoryMapT GetGroupedMemoryMap(
		const MemoryMapT& mm, const std::function<bool(const MemInfoT&)>& filter);

	static std::wstring GetImageNameByAddress(HANDLE hProcess, PTR_T<arch> address, const Wow64Helper<arch>& api);
};
