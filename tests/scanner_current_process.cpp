#include <set>
#include <vector>

#include "callbacks.hpp"
#include "file.hpp"
#include "log.hpp"
#include "memdatasource.hpp"
#include "memhelper.hpp"
#include "pe.hpp"
#include "scanner.hpp"

const void* expectedAddress = nullptr;
std::set<std::string> yaraDetections;
std::wstring currentProcessName;

class TestCallbacks : public DefaultCallbacks
{
public:
	TestCallbacks() : 
		DefaultCallbacks(DefaultCallbacks::ScanningTarget{}, DefaultCallbacks::ScanningGeneralSettings{})
	{}

	void OnProcessScanBegin(uint32_t processId, LARGE_INTEGER creationTime, HANDLE hProcess, const std::wstring& processName)
	{
		currentProcessName = processName;
		DefaultCallbacks::OnProcessScanBegin(processId, creationTime, hProcess, processName);
	}

	void OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT& continiousRegions,
		const std::vector<uint64_t>& threadEntryPoints, bool& scanWithYara) override
	{
		DefaultCallbacks::OnSuspiciousMemoryRegionFound(continiousRegions, threadEntryPoints, scanWithYara);
		if ((uintptr_t)expectedAddress == continiousRegions.front().AllocationBase)
			expectedAddress = nullptr;
	}

	void OnYaraScan(const MemoryHelperBase::MemInfoT64&, uint64_t, uint64_t, bool,
		bool, bool, const std::set<std::string>& detections) override
	{
		yaraDetections.insert(detections.begin(), detections.end());
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

	expectedAddress = address;
	auto callbacks = std::make_shared<TestCallbacks>();
	auto& scanner = MemoryScanner::GetInstance();
	scanner.SetYaraRules(predefinedRules);
	scanner.Scan(GetCurrentProcessId(), callbacks);

	return yaraDetections.find("PeSig") != yaraDetections.end() && expectedAddress == nullptr && currentProcessName == L"scanner_process_test.exe";
}

int main()
{
#if _M_AMD64
	return MapAndCheckPeCopy<CPUArchitecture::X64>() ? 0 : 1;
#else
	return MapAndCheckPeCopy<CPUArchitecture::X86>() ? 0 : 1;
#endif // !_M_AMD64
}
