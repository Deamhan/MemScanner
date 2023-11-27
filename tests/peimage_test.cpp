#include "file.hpp"
#include "memdatasource.hpp"
#include "memhelper.hpp"
#include "pe.hpp"

template <CPUArchitecture arch>
int CheckPE(DataSource& mapped, const char* nameOfFunc)
{
	try
	{
		auto imagePath = GetMemoryHelper().GetImageNameByAddress(GetCurrentProcess(), mapped.GetOrigin());
		PE<false, arch> imageOnDisk(std::make_shared<File>(imagePath.c_str()));
		
		std::vector<std::shared_ptr<ExportedFunctionDescription>> result;
		imageOnDisk.CheckExportForHooks(mapped, result);

		for (const auto& hook : result)
		{
			for (const auto& name : hook->names)
			{
				if (name == nameOfFunc)
					return 0;
			}
		}

		return 11;
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
	DataSourceFragment fragment(moduleMapped, 0x1000);

	return CheckPE<CURRENT_MODULE_ARCH>(fragment, "EnumDeviceDrivers");
}
