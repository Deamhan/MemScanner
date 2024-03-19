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
		
		std::vector<HookDescription> result;
		imageOnDisk.CheckExportForHooks(mapped, result);

		for (const auto& hook : result)
		{
			for (const auto& name : hook.functionDescription->names)
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
	auto dllHandle = LoadLibraryW(L"kernel32");
	if (dllHandle == nullptr)
		return 1;

	MemoryHelperBase::MemoryMapT result;
	bool isAlignedAllocation = false;
	MemoryHelperBase::MemoryMapConstIteratorT begin, end;
	GetMemoryHelper().UpdateMemoryMapForAddr(GetCurrentProcess(), (uintptr_t)dllHandle, result, begin, end, isAlignedAllocation);
	std::vector<std::unique_ptr<ReadOnlyMemoryDataSource>> fragments;

	auto allocationBase = result.begin()->second.AllocationBase;
	CompositeReadOnlyDataSource compositeDs{ allocationBase };
	for (const auto& region : result)
	{
		const auto& regionInfo = region.second;
		if (!MemoryHelperBase::IsReadableRegion(regionInfo))
			continue;

		fragments.emplace_back(new ReadOnlyMemoryDataSource(GetCurrentProcess(), regionInfo.BaseAddress, regionInfo.RegionSize));
		compositeDs.AddDataSource(regionInfo.BaseAddress - regionInfo.AllocationBase, fragments.rbegin()->get());
	}
	
	const wchar_t* fName = L"./compositeDump.dll";
	{
		File dump(fName, File::CreateNew);
		compositeDs.Dump(dump, 0, compositeDs.GetSize(), 1024 * 1024, false);
	}

	File loadedDump(fName);
	for (const auto& ds : fragments)
	{
		uint32_t a, b;
		const uint64_t disp = 100;
		ds->Read(disp, a);
		loadedDump.Read(ds->GetOrigin() - allocationBase + disp, b);

		if (a != b)
			return 1;
	}

	return 0;
}
