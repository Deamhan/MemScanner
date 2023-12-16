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
	GetMemoryHelper().UpdateMemoryMapForAddr(GetCurrentProcess(), (uintptr_t)ntdllHandle, result);

	YaraScanner predefinedScanner{ rules };
	rules = std::make_shared<YaraScanner::YaraRules>(myNewRules);

	YaraScanner myScanner{ rules };

	std::list<std::string> predefinedResult, myResult;
	ScanUsingYara(predefinedScanner, GetCurrentProcess(), result.begin()->second, predefinedResult);
	ScanUsingYara(myScanner, GetCurrentProcess(), result.begin()->second, myResult);

	bool passed = myResult.empty() 
		&& std::find(predefinedResult.begin(), predefinedResult.end(), "PeSig") != predefinedResult.end();

	return passed ? 0 : 1;
}
