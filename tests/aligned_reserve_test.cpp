#include "memdatasource.hpp"
#include "memhelper.hpp"
#include "pe.hpp"
#include "yara.hpp"

const std::list<std::string> rules{ "\
            rule AlignedExecPrivateAllocation { \
              condition: \
                (MemoryType == PrivateType) and ((MemoryAttributes & XFlag) != 0) and (AlignedAllocation != 0)\
             }" };

int main()
{
	auto reservedSpace = VirtualAlloc(nullptr, 0x10000, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (reservedSpace == nullptr)
		return 1;

	auto allocatedSpace = VirtualAlloc(reservedSpace, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	auto scanner = BuildYaraScanner(rules);
	if (!scanner)
		return false;

	bool isAlignedAllocation = false;
	MemoryHelperBase::MemoryMapT result;
	GetMemoryHelper().UpdateMemoryMapForAddr(GetCurrentProcess(), (uintptr_t)allocatedSpace, result, isAlignedAllocation);

	std::set<std::string> yaraResult;
	uint64_t startAddress = 0, size = 0;
	ScanUsingYara(*scanner, GetCurrentProcess(), result.begin()->second, yaraResult, startAddress, size, false, false, isAlignedAllocation);

	return std::find(yaraResult.begin(), yaraResult.end(), "AlignedExecPrivateAllocation") != yaraResult.end() ? 0 : 1;
}
