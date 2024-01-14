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
	GetMemoryHelper().UpdateMemoryMapForAddr(GetCurrentProcess(), (uintptr_t)ntdllHandle, result, isAlignedAllocation);

	auto scanner = BuildYaraScanner(YARA_RULES_DIR);
	std::list<std::string> yaraResult;
	ScanUsingYara(*scanner, GetCurrentProcess(), result.begin()->second, yaraResult);

	return std::find(yaraResult.begin(), yaraResult.end(), "PeSig") != yaraResult.end() ? 0 : 1;
}
