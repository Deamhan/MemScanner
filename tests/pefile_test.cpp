#include "file.hpp"
#include "pe.hpp"

typedef std::map<uint16_t, ExportedFunctionDescription> OrdinalMapT;
typedef std::map<uint32_t, ExportedFunctionDescription> RvaMapT;

static OrdinalMapT RvaToOrdinalMap(const RvaMapT& rvaMap)
{
	OrdinalMapT result;
	for (const auto& item : rvaMap)
		result.emplace(item.second.ordinal, item.second);

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
		if (it1->second.names.size() != it2->second.names.size())
			return false;

		if (!std::equal(it1->second.names.begin(), it1->second.names.end(), it2->second.names.begin()))
			return false;
	}

	return true;
}

template <CPUArchitecture arch>
int CheckPE(ReadOnlyDataSource& file, ReadOnlyDataSource& mapped)
{
	try
	{
		PEFile<false, arch> peFile(file);
		peFile.BuildExportMap();

		PEFile<true, arch> peMapped(mapped);
		peMapped.BuildExportMap();

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
	std::vector<WCHAR> pathBuffer(32 * 1024, L'\0');
	auto ntdllHandle = GetModuleHandleW(L"ntdll");
	if (ntdllHandle == nullptr)
		return 1;

	if (0 == GetModuleFileNameW(ntdllHandle, pathBuffer.data(), pathBuffer.size() - 1))
		return 2;

	ReadOnlyFile ntdllFile { pathBuffer.data() };

	ReadOnlyMemoryDataSource ntdllMapped(GetCurrentProcess(), (uintptr_t)ntdllHandle, 100 * 1024 * 1024);

	switch (PEFile<>::GetPeArch(ntdllFile))
	{
	case CPUArchitecture::X86:
		return CheckPE<CPUArchitecture::X86>(ntdllFile, ntdllMapped);

	case CPUArchitecture::X64:
		return CheckPE<CPUArchitecture::X64>(ntdllFile, ntdllMapped);

	default:
		return 3;
	}
}
