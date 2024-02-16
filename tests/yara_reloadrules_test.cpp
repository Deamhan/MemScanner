#include <algorithm>

#include "callbacks.hpp"
#include "file.hpp"
#include "memdatasource.hpp"
#include "memhelper.hpp"
#include "pe.hpp"
#include "yara.hpp"


const std::list<std::string> myNewRules{ "\
            rule PeSigPrivate { \
              strings: \
                $dosText = \"This program cannot be run in DOS mode\" \
                $PeMagic = { 45 50 00 00 } \
                $TextSec = \".text\" \
                $CodeSec = \".code\" \
              condition: \
                (MemoryType == PrivateType) and (($dosText and ($TextSec or $CodeSec)) or ($PeMagic and ($TextSec or $CodeSec)))\
             }" };

int main()
{
	std::thread t;
	auto rules = std::make_shared<YaraScanner::YaraRules>(predefinedRules);

	auto ntdllHandle = GetModuleHandleW(L"ntdll");
	if (ntdllHandle == nullptr)
		return 1;

	MemoryHelperBase::MemoryMapT result;
	bool isAlignedAllocation = false;
	GetMemoryHelper().UpdateMemoryMapForAddr(GetCurrentProcess(), (uintptr_t)ntdllHandle, result, isAlignedAllocation);

	YaraScanner predefinedScanner{ rules };
	rules = std::make_shared<YaraScanner::YaraRules>(myNewRules);

	YaraScanner myScanner{ rules };

	std::set<std::string> predefinedResult, myResult;
	uint64_t startAddress = 0, size = 0;
	ScanUsingYara(predefinedScanner, GetCurrentProcess(), result.begin()->second, predefinedResult, startAddress, size);
	startAddress = 0, size = 0;
	ScanUsingYara(myScanner, GetCurrentProcess(), result.begin()->second, myResult, startAddress, size);

	bool passed = myResult.empty() 
		&& predefinedResult.find("PeSig") != predefinedResult.end();

	return passed ? 0 : 1;
}
