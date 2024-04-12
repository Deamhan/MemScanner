#include "callbacks.hpp"
#include "file.hpp"
#include "memdatasource.hpp"
#include "memhelper.hpp"
#include "pe.hpp"
#include "yara.hpp"

const std::list<std::string> RangedPeSig{ "\
            rule PeSig { \
              strings: \
                $dosText = \"This program cannot be run in DOS mode\" \
              condition: \
                $dosText in (OperationRangeStart..OperationRangeEnd)\
             }" };

const std::list<std::string> UnrangedPeSig{ "\
            rule PeSig { \
              strings: \
                $dosText = \"This program cannot be run in DOS mode\" \
              condition: \
                $dosText in (0..filesize)\
             }" };

bool YaraTest(HMODULE hModule, const std::list<std::string>& yaraRules)
{
    MemoryHelperBase::MemoryMapT result;
    bool isAlignedAllocation = false;
    MemoryHelperBase::MemoryMapConstIteratorT begin, end;
    auto range = GetMemoryHelper().UpdateMemoryMapForAddr(GetCurrentProcess(), (uintptr_t)hModule, result, begin, end, isAlignedAllocation);

    auto scanner = BuildYaraScanner(yaraRules);
    std::set<std::string> yaraResult;
    uint64_t startAddress = (uintptr_t)hModule + 0x400, size = 0x100;
    ScanUsingYara(*scanner, GetCurrentProcess(), range, yaraResult, startAddress, size);

    return !yaraResult.empty();
}

int main()
{
	auto ntdllHandle = GetModuleHandleW(L"ntdll");
	if (ntdllHandle == nullptr)
		return 1;

    bool passed = !YaraTest(ntdllHandle, RangedPeSig) && YaraTest(ntdllHandle, UnrangedPeSig);
    return passed ? 0 : 1;
}
