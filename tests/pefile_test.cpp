#include "file.hpp"
#include "memhelper.hpp"
#include "pe.hpp"

typedef std::map<uint16_t, std::shared_ptr<ExportedFunctionDescription>> OrdinalMapT;
typedef std::map<uint32_t, std::shared_ptr<ExportedFunctionDescription>> RvaMapT;

static OrdinalMapT RvaToOrdinalMap(const RvaMapT& rvaMap)
{
	OrdinalMapT result;
	for (const auto& item : rvaMap)
		result.emplace(item.second->ordinal, item.second);

	return result;
}

template <CPUArchitecture arch>
bool CompareExportMaps(const OrdinalMapT& m1,
	const OrdinalMapT& m2)
{
	if (m1.size() != m2.size())
		return false;

	auto it1 = m1.begin(), it2 = m2.begin();
	int count = 0;
	for (; it1 != m1.end(); ++it1, ++it2, ++count)
	{
		if (it1->second->names.size() != it2->second->names.size())
			return false;

		if (!std::equal(it1->second->names.begin(), it1->second->names.end(), it2->second->names.begin()))
			return false;
	}

	return true;
}

static std::wstring GetImageName(std::shared_ptr<ReadOnlyMemoryDataSource> mapped)
{
	return GetMemoryHelper().GetImageNameByAddress(GetCurrentProcess(), mapped->GetOrigin());
}

template <CPUArchitecture arch>
int CheckPE(std::shared_ptr<File> file, std::shared_ptr<ReadOnlyMemoryDataSource> mapped)
{
	try
	{
		PE<false, arch> peFile(file);
		PE<true, arch> peMapped(mapped);

		if (!CompareExportMaps<arch>(RvaToOrdinalMap(peFile.GetExportMap()), RvaToOrdinalMap(peMapped.GetExportMap())))
			return 11;

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

	auto ntdllMapped = std::make_shared<ReadOnlyMemoryDataSource>(GetCurrentProcess(), (uintptr_t)ntdllHandle, 100 * 1024 * 1024);

	auto ntdllFile = std::make_shared<File>(GetImageName(ntdllMapped).c_str());

	switch (PE<>::GetPeArch(ntdllMapped))
	{
	case CPUArchitecture::X86:
		return CheckPE<CPUArchitecture::X86>(ntdllFile, ntdllMapped);
	case CPUArchitecture::X64:
		return CheckPE<CPUArchitecture::X64>(ntdllFile, ntdllMapped);

	default:
		return 3;
	}
}
