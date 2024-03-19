#include "callbacks.hpp"
#include "file.hpp"
#include "memdatasource.hpp"
#include "memhelper.hpp"
#include "pe.hpp"
#include "yara.hpp"

int main()
{
	auto ntdllHandle = GetModuleHandleW(L"ntdll");
	if (ntdllHandle == nullptr)
		return 1;

	MemoryHelperBase::MemoryMapT result;
	bool isAlignedAllocation = false;
	MemoryHelperBase::MemoryMapConstIteratorT begin, end;
	GetMemoryHelper().UpdateMemoryMapForAddr(GetCurrentProcess(), (uintptr_t)ntdllHandle, result, begin, end, isAlignedAllocation);

	auto scanner = BuildYaraScanner(YARA_RULES_DIR);
	std::set<std::string> yaraResult;
	uint64_t startAddress = 0, size = 0;
	ScanUsingYara(*scanner, GetCurrentProcess(), result.begin()->second, yaraResult, startAddress, size);

	return std::find(yaraResult.begin(), yaraResult.end(), "PeSig") != yaraResult.end() ? 0 : 1;
}
