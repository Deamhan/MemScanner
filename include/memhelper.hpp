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

	using MemInfoT64 = SystemDefinitions::MEMORY_BASIC_INFORMATION_T<uint64_t>;
	using MemoryMapT = std::map<uint64_t, MemInfoT64>;
	using FlatMemoryMapT = std::vector<MemInfoT64>;
	using GroupedMemoryMapT = std::map<uint64_t, FlatMemoryMapT>;

	static GroupedMemoryMapT GetGroupedMemoryMap(
		const MemoryMapT& mm, const std::function<bool(const MemInfoT64&)>& filter);

	static FlatMemoryMapT GetFlatMemoryMap(
		const MemoryMapT& mm, const std::function<bool(const MemInfoT64&)>& filter);

	virtual std::wstring GetImageNameByAddress(HANDLE hProcess, uint64_t address) const = 0;
	virtual MemoryMapT GetMemoryMap(HANDLE hProcess) const = 0;
	virtual bool GetBasicInfoByAddress(HANDLE hProcess, uint64_t address, MemInfoT64& result) const = 0;
};

template <CPUArchitecture arch>
class MemoryHelper : public MemoryHelperBase
{
public:
	using MemInfoT = SystemDefinitions::MEMORY_BASIC_INFORMATION_T<PTR_T<arch>>;

    std::wstring GetImageNameByAddress(HANDLE hProcess, uint64_t address) const override;
    MemoryMapT GetMemoryMap(HANDLE hProcess) const override;
    bool GetBasicInfoByAddress(HANDLE hProcess, uint64_t address, MemInfoT64& result) const override;

	MemoryHelper() : mApi(GetWow64Helper<arch>()) {}

private:
	static MemInfoT64 ConvertToMemoryBasicInfo64(const MemInfoT& mbi);
	const Wow64Helper<arch>& mApi;
};

template <CPUArchitecture arch>
const MemoryHelper<arch>& GetMemoryHelperForArch();

const MemoryHelperBase& GetMemoryHelper() noexcept;