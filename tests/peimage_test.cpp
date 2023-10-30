#include "file.hpp"
#include "memhelper.hpp"
#include "pe.hpp"

template <CPUArchitecture arch>
int CheckPE(ReadOnlyDataSource& mapped)
{
	try
	{
		PE<true, arch> peMapped(mapped);
		peMapped.BuildExportMap();

		auto& api = GetWow64Helper<arch>();
		auto imagePath = MemoryHelper<arch>::GetImageNameByAddress(GetCurrentProcess(), (PTR_T<arch>)mapped.GetOffset(), api);

		ReadOnlyFile fileOnDisk{ imagePath.c_str() };
		PE<false, arch> imageOnDisk(fileOnDisk);
		
		auto result = peMapped.CheckExportForHooks(imageOnDisk);

		return result.size() == 1 ? 0 : 11; // can fail if there are unexpected hooks
	}
	catch (const PeException&)
	{
		return 10;
	}
}

int main()
{
	auto moduleHandle = GetModuleHandleW(L"kernelbase");
	if (moduleHandle == nullptr)
		return 1;

	auto ptr = (uint8_t*)GetProcAddress(moduleHandle, "EnumDeviceDrivers");
	DWORD oldProt = 0;
	if (!VirtualProtect(ptr, 0x1000, PAGE_EXECUTE_READWRITE, &oldProt))
		return 4;

	*ptr = 0xe9;

	ReadOnlyMemoryDataSource moduleMapped(GetCurrentProcess(), (uintptr_t)moduleHandle - 0x1000, 100 * 1024 * 1024);
	DataSourceFragment fragment(moduleMapped, 0x1000, 50 * 1024 * 1024);

	return CheckPE<CURRENT_MODULE_ARCH>(fragment);
}
