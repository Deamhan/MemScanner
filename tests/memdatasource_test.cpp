#include "pe.hpp"

template <CPUArchitecture arch>
int CheckPE(ReadOnlyDataSource& ds)
{
	try
	{
		PEFile<true, arch> pe(ds);
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
	auto ntdllHandle = GetModuleHandleW(L"ntdll");
	if (ntdllHandle == nullptr)
		return 1;

	ReadOnlyMemoryDataSource ntdllShifted(GetCurrentProcess(), (uintptr_t)ntdllHandle - 0x1000, 100 * 1024 * 1024);
	DataSourceFragment fragment(ntdllShifted, 0x1000, 50 * 1024 * 1024);

	switch (PEFile<>::GetPeArch(fragment))
	{
#if !_M_AMD64
	case CPUArchitecture::X86:
		return CheckPE<CPUArchitecture::X86>(fragment);
#endif //  !_M_AMD64
	case CPUArchitecture::X64:
		return CheckPE<CPUArchitecture::X64>(fragment);

	default:
		return 2;
	}
}
