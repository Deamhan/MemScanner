#include "memdatasource.hpp"
#include "memhelper.hpp"
#include "pe.hpp"
#include "yara.hpp"

const std::list<std::string> rules{ "\
            rule PeSigPrivate { \
              strings: \
                $dosText = \"This program cannot be run in DOS mode\" \
                $PeMagic = { 45 50 00 00 } \
                $TextSec = \".text\" \
                $CodeSec = \".code\" \
              condition: \
                (MemoryType == PrivateType) and (($dosText and ($TextSec or $CodeSec)) or ($PeMagic and ($TextSec or $CodeSec)))\
             }" };


template <CPUArchitecture arch>
static PVOID MapPeCopy()
{
	auto moduleHandle = GetModuleHandleW(L"kernelbase");
	if (moduleHandle == nullptr)
		return false;

	auto moduleMapped = std::make_shared<ReadOnlyMemoryDataSource>(GetCurrentProcess(), (uintptr_t)moduleHandle, 100 * 1024 * 1024);
	PE<true, arch> peMapped(moduleMapped);

	auto size = peMapped.GetImageSize();
	auto address = VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (address == nullptr)
		return false;

	memcpy((char*)address, moduleHandle, size);

	return address;
}

static bool ScanImage()
{
	auto ntdllHandle = GetModuleHandleW(L"kernelbase");
	if (ntdllHandle == nullptr)
		return false;

	MemoryHelperBase::MemoryMapT result;
	bool isAlignedAllocation = false;
	GetMemoryHelper().UpdateMemoryMapForAddr(GetCurrentProcess(), (uintptr_t)ntdllHandle, result, isAlignedAllocation);

	auto scanner = BuildYaraScanner(rules);
	if (!scanner)
		return false;

	std::list<std::string> yaraResult;
	ScanUsingYara(*scanner, GetCurrentProcess(), result.begin()->second, yaraResult);

	return yaraResult.empty();
}

static bool ScanCopy()
{
#if _M_AMD64
	auto copyAddr = MapPeCopy<CPUArchitecture::X64>();
#else
	auto copyAddr = MapPeCopy<CPUArchitecture::X86>();
#endif // !_M_AMD64

	if (copyAddr == nullptr)
		return false;

	MemoryHelperBase::MemoryMapT result;
	bool isAlignedAllocation = false;
	GetMemoryHelper().UpdateMemoryMapForAddr(GetCurrentProcess(), (uintptr_t)copyAddr, result, isAlignedAllocation);

	auto scanner = BuildYaraScanner(rules);
	if (!scanner)
		return false;

	std::list<std::string> yaraResult;
	ScanUsingYara(*scanner, GetCurrentProcess(), result.begin()->second, yaraResult);

	return std::find(yaraResult.begin(), yaraResult.end(), "PeSigPrivate") != yaraResult.end();
}

int main()
{
	return ScanImage() && ScanCopy() ? 0 : 1;
}
