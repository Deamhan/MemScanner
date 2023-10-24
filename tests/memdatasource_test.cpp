#include "pe.hpp"

template <CPUArchitecture arch>
int CheckPE(ReadOnlyDataSource& ds)
{
	try
	{
		DataSourceFragment fragment(ds, 0x1000, 50 * 1024 * 1024);
		MappedPEFile<arch> pe(fragment);
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

	ReadOnlyMemoryDataSource ntdll(GetCurrentProcess(), (uintptr_t)selfBase - 0x1000, 100 * 1024 * 1024);

	return MappedPEFile<>::GetPeArch(ntdll) == CPUArchitecture::X64 ?
		CheckPE<CPUArchitecture::X64>(ntdll) : CheckPE<CPUArchitecture::X86>(ntdll);
}
