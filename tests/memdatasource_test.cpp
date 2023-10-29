#include "memhelper.hpp"
#include "file.hpp"
#include "pe.hpp"

template <CPUArchitecture arch>
int CheckPE(ReadOnlyDataSource& ds)
{
	try
	{
		PE<true, arch> pe(ds);
		pe.BuildExportMap();

		auto& api = GetWow64Helper<arch>();
		auto imagePath = MemoryHelper<arch>::GetImageNameByAddress(GetCurrentProcess(), (PTR_T<arch>)ds.GetOffset(), api);

		ReadOnlyFile fileOnDisk{ imagePath.c_str()};
		PE<false, arch> imageOnDisk(fileOnDisk);

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

	switch (PE<>::GetPeArch(fragment))
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
