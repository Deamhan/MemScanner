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
	GetMemoryHelper().UpdateMemoryMapForAddr(GetCurrentProcess(), (uintptr_t)ntdllHandle, result);

	std::list<std::string> yaraResult;
	YaraScanner scanner;
	LoadYaraRules(scanner, YARA_RULES_DIR);
	ScanUsingYara(scanner, GetCurrentProcess(), result.begin()->second, yaraResult);

	return std::find(yaraResult.begin(), yaraResult.end(), "PeSig") != yaraResult.end() ? 0 : 1;
}
