#include "pe.hpp"

template <CPUArchitecture arch>
int CheckPE(ReadOnlyMemoryDataSource& ds, uint64_t offset)
{
	try
	{
		MappedPEFile<arch> pe(ds, offset);
		pe.BuildExportMap();

		return 0;
	}
	catch (const PeException&)
	{
		return 10;
	}
}

int main()
{
	std::vector<WCHAR> buffer(120 * 1024);
	auto selfBase = GetModuleHandleW(L"ntdll");
	if (selfBase == nullptr)
		return 1;

	ReadOnlyMemoryDataSource ntdll(GetCurrentProcess(), (uintptr_t)selfBase, 100 * 1024 * 1024);
	return MappedPEFile<>::GetPeArch(ntdll, 0) == CPUArchitecture::X64 ?
		CheckPE<CPUArchitecture::X64>(ntdll, 0) : CheckPE<CPUArchitecture::X86>(ntdll, 0);
}
