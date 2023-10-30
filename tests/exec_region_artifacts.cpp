#include <vector>

#include "file.hpp"
#include "log.hpp"
#include "memhelper.hpp"
#include "pe.hpp"

static bool IsSectionBorder(const std::vector<uint8_t>& buffer)
{
	for (size_t i = 0; i < buffer.size() / 2; ++i)
	{
		if (buffer[i] != 0)
			return false;
	}

	size_t NonZeroAmount = 0;
	for (size_t i = buffer.size() / 2; i < buffer.size(); ++i)
	{
		if (buffer[i] != 0)
			++NonZeroAmount;
	}

	return NonZeroAmount * 8 >= buffer.size();
}

template <CPUArchitecture arch>
static std::vector<uint64_t> ScanCurrentProcessMemoryForSectionBorders()
{
	Timer timer;
	std::vector<uint64_t> result;

	auto& api = GetWow64Helper<arch>();

	auto mm = MemoryHelper<arch>::GetMemoryMap(GetCurrentProcess(), api);
	auto groupedMm = MemoryHelper<arch>::GetGroupedMemoryMap(mm, [](const SystemDefinitions::MEMORY_BASIC_INFORMATION_T<PTR_T<arch>>& mbi)
		{
			return mbi.Type != SystemDefinitions::MemType::Image;
		});

	ReadOnlyMemoryDataSource memory(GetCurrentProcess(), 0, 0xffffffffffffffffull);

	for (const auto& group : groupedMm)
	{
		auto& trailingRegion = *group.second.rbegin();
		auto beginAddr = trailingRegion.AllocationBase;
		auto endAddr = trailingRegion.BaseAddress + trailingRegion.RegionSize;

		auto len = endAddr - beginAddr;
		if (len < 32 * 1024)
			continue;

		bool isExecRelated = false;
		for (const auto& region : group.second)
		{
			if ((MemoryHelper<arch>::protToFlags(region.Protect) & MemoryHelper<arch>::XFlag) != 0)
			{
				isExecRelated = true;
				break;
			}
		}

		if (!isExecRelated)
			continue;

		std::vector<uint8_t> buffer(64 * 2);
		uint32_t bordersCount = 0;
		for (uint64_t offs = beginAddr + PAGE_SIZE; offs < endAddr; offs += PAGE_SIZE)
		{
			try
			{
				memory.Read(offs - buffer.size() / 2, buffer.data(), buffer.size());
				if (!IsSectionBorder(buffer))
					continue;

				++bordersCount;
			}
			catch (const DataSourceException&) {}
		}

		if (len / bordersCount > 12 * 1024)
			result.push_back(beginAddr);
	}

	return result;
}

template <CPUArchitecture arch>
static int MapAndCheckPeCopy()
{
	auto moduleHandle = GetModuleHandleW(L"kernelbase");
	if (moduleHandle == nullptr)
		return 1;

	ReadOnlyMemoryDataSource moduleMapped(GetCurrentProcess(), (uintptr_t)moduleHandle, 100 * 1024 * 1024);
	PE<true, arch> peMapped(moduleMapped);

	const uintptr_t offset = 0;
	auto size = peMapped.GetImageSize();
	auto address = VirtualAlloc(nullptr, size + offset, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (address == nullptr)
		return 2;

	memcpy((char*)address + offset, moduleHandle, size);

	SetDefaultLogger(&GetConsoleLoggerInstance());

	auto bordersFound = ScanCurrentProcessMemoryForSectionBorders<arch>();

	return bordersFound.size() == 1 ? 0 : 3; // I assume that there is no other PEs in private memory
}

int main()
{
#if _M_AMD64
	return MapAndCheckPeCopy<CPUArchitecture::X64>();
#else
	return MapAndCheckPeCopy<CPUArchitecture::X86>();
#endif // !_M_AMD64
}
