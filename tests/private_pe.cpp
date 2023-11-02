#include <vector>

#include "file.hpp"
#include "log.hpp"
#include "memhelper.hpp"
#include "pe.hpp"

static size_t ScanBlobForMz(const std::vector<uint8_t>& buffer, size_t offset)
{
	for (size_t i = offset; i < buffer.size() - 1; ++i)
	{
		if (*(uint16_t*)(buffer.data() + i) == 0x5a4d)
			return i;
	}

	return buffer.size();
}

static uint64_t ScanCurrentProcessMemoryForPe()
{
	Timer timer;

	auto mm = GetMemoryHelper().GetMemoryMap(GetCurrentProcess());
	auto groupedMm = MemoryHelperBase::GetGroupedMemoryMap(mm, [](const SystemDefinitions::MEMORY_BASIC_INFORMATION_T<uint64_t>& mbi)
		{
			return mbi.Type != SystemDefinitions::MemType::Image;
		});

	ReadOnlyMemoryDataSource memory(GetCurrentProcess(), 0, 0xffffffffffffffffull);

	for (const auto& group : groupedMm)
	{
		auto& trailingRegion = *group.second.rbegin();
		auto beginAddr = trailingRegion.AllocationBase;
		auto endAddr = trailingRegion.BaseAddress + trailingRegion.RegionSize;

		bool isExecRelated = false;
		for (const auto& region : group.second)
		{
			if ((MemoryHelperBase::protToFlags(region.Protect) & MemoryHelperBase::XFlag) != 0)
			{
				isExecRelated = true;
				break;
			}
		}

		if (!isExecRelated)
			continue;

		std::vector<uint8_t> buffer(64 * 1024);
		for (uint64_t offs = beginAddr; offs < endAddr; offs += buffer.size())
		{
			try
			{
				memory.Read(beginAddr, buffer.data(), buffer.size());
				size_t mzPos = 0;
				do
				{
					mzPos = ScanBlobForMz(buffer, mzPos);
					if (mzPos == buffer.size())
						break;

					DataSourceFragment fragment(memory, beginAddr + mzPos, 50 * 1024 * 1024);
					if (PE<>::GetPeArch(fragment) != CPUArchitecture::Unknown)
						return fragment.GetOffset();

					mzPos += 2;
				} while (true);
			}
			catch (const DataSourceException&) {}
		}
	}

	return 0;
}

template <CPUArchitecture arch>
static bool MapAndCheckPeCopy()
{
	auto moduleHandle = GetModuleHandleW(L"kernelbase");
	if (moduleHandle == nullptr)
		return false;

	ReadOnlyMemoryDataSource moduleMapped(GetCurrentProcess(), (uintptr_t)moduleHandle, 100 * 1024 * 1024);
	PE<true, arch> peMapped(moduleMapped);

	const uintptr_t offset = 0x123;
	auto size = peMapped.GetImageSize();
	auto address = VirtualAlloc(nullptr, size + offset, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (address == nullptr)
		return false;

	memcpy((char*)address + offset, moduleHandle, size);

	SetDefaultLogger(&GetConsoleLoggerInstance());

	return ScanCurrentProcessMemoryForPe() == (uintptr_t)moduleHandle + offset; // I assume that there is no other PEs in private memory
}

int main()
{
#if _M_AMD64
	return MapAndCheckPeCopy<CPUArchitecture::X64>();
#else
	return MapAndCheckPeCopy<CPUArchitecture::X86>();
#endif // !_M_AMD64
}
