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
	static void CloseSearchHandleByPtr(HANDLE* handle);
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
	using MemoryMapConstIteratorT = MemoryMapT::const_iterator;
	using FlatMemoryMapT = std::vector<MemInfoT64>;
	using FlatMemoryMapConstIteratorT = FlatMemoryMapT::const_iterator;
	using GroupedMemoryMapT = std::map<uint64_t, FlatMemoryMapT>;

	static GroupedMemoryMapT GetGroupedMemoryMap(
		const MemoryMapT& mm, const std::function<bool(const MemInfoT64&)>& filter);

	static FlatMemoryMapT GetFlatMemoryMap(
		const MemoryMapT& mm, const std::function<bool(const MemInfoT64&)>& filter);

	static bool IsAlignedAllocation(const FlatMemoryMapT& mm);
	static bool IsReadableRegion(const MemInfoT64& region);
	static uint64_t GetTopReadableBorder(const FlatMemoryMapT& mm);

	virtual uint64_t GetHighestUsermodeAddress() const = 0;

	virtual std::wstring GetImageNameByAddress(HANDLE hProcess, uint64_t address) const = 0;
	virtual MemoryMapT GetMemoryMap(HANDLE hProcess) const = 0;
	virtual MemInfoT64 UpdateMemoryMapForAddr(HANDLE hProcess, uint64_t addressToCheck, MemoryMapT& result, 
		MemoryMapConstIteratorT& rangeBegin, MemoryMapConstIteratorT& rangeEnd, bool& isAllocationAligned) const = 0;
	virtual bool GetBasicInfoByAddress(HANDLE hProcess, uint64_t address, MemInfoT64& result) const = 0;

	struct ImageDescription
	{
		uint64_t BaseAddress;
		uint32_t ImageSize;
		std::wstring ImagePath;
		CPUArchitecture Architecture;

		template <class StrT> 
		ImageDescription(uint64_t baseAddress, uint32_t imageSize, CPUArchitecture arch, StrT&& imagePath) noexcept :
			BaseAddress(baseAddress), ImageSize(imageSize), ImagePath(std::forward<StrT>(imagePath)), Architecture(arch)
		{}
	};

	virtual std::vector<ImageDescription> GetImageDataFromPeb(HANDLE hProcess) const = 0;
};

template <CPUArchitecture arch>
class MemoryHelper final : public MemoryHelperBase
{
public:
	using MemInfoT = SystemDefinitions::MEMORY_BASIC_INFORMATION_T<PTR_T<arch>>;

    std::wstring GetImageNameByAddress(HANDLE hProcess, uint64_t address) const override;
    MemoryMapT GetMemoryMap(HANDLE hProcess) const override;
	MemInfoT64 UpdateMemoryMapForAddr(HANDLE hProcess, uint64_t addressToCheck, MemoryMapT& result, 
		MemoryMapConstIteratorT& rangeBegin, MemoryMapConstIteratorT& rangeEnd, bool& isAllocationAligned) const override;
    bool GetBasicInfoByAddress(HANDLE hProcess, uint64_t address, MemInfoT64& result) const override;

    uint64_t GetHighestUsermodeAddress() const override;

    std::vector<ImageDescription> GetImageDataFromPeb(HANDLE hProcess) const override;

	MemoryHelper() : mApi(GetWow64Helper<arch>()) {}

private:
	static MemInfoT64 ConvertToMemoryBasicInfo64(const MemInfoT& mbi);
	const Wow64Helper<arch>& mApi;

	static thread_local std::vector<uint8_t> ImageNameBuffer;
};

template <CPUArchitecture arch>
const MemoryHelper<arch>& GetMemoryHelperForArch();

const MemoryHelperBase& GetMemoryHelper() noexcept;

const uint32_t PAGE_SIZE = 4096;

template <class T>
inline T PageAlignUp(T value) { return (value + PAGE_SIZE - 1) & (~((T)PAGE_SIZE - 1)); }

template <class T>
inline T PageAlignDown(T value) { return value& (~((T)PAGE_SIZE - 1)); }
