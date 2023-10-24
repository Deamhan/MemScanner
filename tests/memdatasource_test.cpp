#include "pe.hpp"

template <CPUArchitecture arch>
int CheckPE(ReadOnlyDataSource& ds)
{
	try
	{
		MappedPEFile<arch> pe(ds);
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

	ReadOnlyMemoryDataSource ntdllShifted(GetCurrentProcess(), (uintptr_t)selfBase - 0x1000, 100 * 1024 * 1024);
	DataSourceFragment fragment(ntdllShifted, 0x1000, 50 * 1024 * 1024);

	switch (MappedPEFile<>::GetPeArch(fragment))
	{
	case CPUArchitecture::X86:
		return CheckPE<CPUArchitecture::X86>(fragment);

	case CPUArchitecture::X64:
		return CheckPE<CPUArchitecture::X64>(fragment);

	default:
		return 2;
	}
}
