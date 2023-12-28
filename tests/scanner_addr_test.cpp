#include <vector>

#include "callbacks.hpp"
#include "file.hpp"
#include "log.hpp"
#include "memdatasource.hpp"
#include "memhelper.hpp"
#include "pe.hpp"
#include "scanner.hpp"

MemoryHelperBase::FlatMemoryMapT detectedMap;

class TestCallbacks : public DefaultCallbacks
{
public:
	TestCallbacks(uint64_t address) : 
		DefaultCallbacks(GetCurrentProcessId(), address, 0, false, false, MemoryScanner::Sensitivity::Low,
			MemoryScanner::Sensitivity::Off, MemoryScanner::Sensitivity::Off)
	{}

	void OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT& continiousRegions,
		const std::vector<uint64_t>& /*threadEntryPoints*/, bool& scanWithYara) override
	{
		scanWithYara = false;
		detectedMap = continiousRegions;
	}
};

template <CPUArchitecture arch>
static bool MapAndCheckPeCopy()
{
	auto moduleHandle = GetModuleHandleW(L"kernelbase");
	if (moduleHandle == nullptr)
		return false;

	auto moduleMapped = std::make_shared<ReadOnlyMemoryDataSource>(GetCurrentProcess(), (uintptr_t)moduleHandle, 100 * 1024 * 1024);
	PE<true, arch> peMapped(moduleMapped);

	const uintptr_t offset = 0x123;
	auto size = peMapped.GetImageSize();

	auto address = VirtualAlloc(nullptr, size + offset, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (address == nullptr)
		return false;

	memcpy((char*)address + offset, moduleHandle, size);

	auto tlsCallbacks = std::make_shared<TestCallbacks>((uintptr_t)address + 0x3000);
	MemoryScanner::GetInstance().Scan(tlsCallbacks);

	if (detectedMap.size() != 1)
		return false;
	
	auto& region = detectedMap[0];
	return region.AllocationBase == region.BaseAddress
		&& region.BaseAddress == (uintptr_t)address && region.RegionSize == PageAlignUp(size + offset);
}

int main()
{
#if _M_AMD64
	return MapAndCheckPeCopy<CPUArchitecture::X64>() ? 0 : 1;
#else
	return MapAndCheckPeCopy<CPUArchitecture::X86>() ? 0 : 1;
#endif // !_M_AMD64
}
