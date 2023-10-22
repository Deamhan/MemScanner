#include "pe.hpp"

#include <algorithm>

template <CPUArchitecture arch>
CPUArchitecture PEFile<arch>::TryParseGeneralPeHeaders(ReadOnlyMemoryDataSource& ds, uint64_t offset,
	IMAGE_DOS_HEADER& dosHeader, IMAGE_FILE_HEADER& fileHeader)
{
	auto err = ds.Seek(offset);
	if (err != DataSourceError::Ok)
		return CPUArchitecture::Unknown;

	err = ds.Read(dosHeader);
	if (err != DataSourceError::Ok)
		return CPUArchitecture::Unknown;

	if (dosHeader.e_magic != 0x5a4d)
		return CPUArchitecture::Unknown;

    err = ds.Seek(dosHeader.e_lfanew + offset);
	if (err != DataSourceError::Ok)
		return CPUArchitecture::Unknown;

	DWORD signature = 0;
	err = ds.Read(signature);
	if (err != DataSourceError::Ok)
		return CPUArchitecture::Unknown;

	err = ds.Read(fileHeader);
	if (err != DataSourceError::Ok)
		return CPUArchitecture::Unknown;

	switch (fileHeader.Machine)
	{
#if !_M_AMD64
	case IMAGE_FILE_MACHINE_I386:
		return CPUArchitecture::X86;
#endif // !_M_AMD64
	case IMAGE_FILE_MACHINE_AMD64:
		return CPUArchitecture::X64;
	default:
		return CPUArchitecture::Unknown;
	}
}

template <CPUArchitecture arch>
PEFile<arch>::PEFile(ReadOnlyMemoryDataSource& ds, uint64_t offset) : mIsPeValid(false), mDataSource(ds), mOffset(offset)
{
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_FILE_HEADER fileHeader;
	auto peArch = TryParseGeneralPeHeaders(mDataSource, mOffset, dosHeader, fileHeader);
	if (peArch != arch)
		return;

	ImageOptionalHeaderT optHeader;
	auto err = ds.Read(optHeader);
	if (err != DataSourceError::Ok)
		return;

	auto sectionsCount = std::min<size_t>(256, fileHeader.NumberOfSections);
	mSections.resize(sectionsCount);

	size_t read = 0;
	err = ds.Read(mSections.data(), mSections.size() * sizeof(IMAGE_SECTION_HEADER), read);
	if (err != DataSourceError::Ok)
		return;

	mIsPeValid = true;
}

template <CPUArchitecture arch>
CPUArchitecture PEFile<arch>::GetPeArch(ReadOnlyMemoryDataSource& ds, uint64_t offset)
{
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_FILE_HEADER fileHeader;
	return TryParseGeneralPeHeaders(ds, offset, dosHeader, fileHeader);
}

#if !_M_AMD64
template CPUArchitecture PEFile<CPUArchitecture::X86>::TryParseGeneralPeHeaders(ReadOnlyMemoryDataSource& ds, uint64_t offset,
	IMAGE_DOS_HEADER& dosHeader, IMAGE_FILE_HEADER& fileHeader);

template PEFile<CPUArchitecture::X86>::PEFile(ReadOnlyMemoryDataSource& ds, uint64_t offset);

template CPUArchitecture PEFile<CPUArchitecture::X86>::GetPeArch(ReadOnlyMemoryDataSource& ds, uint64_t offset);
#endif // !_M_AMD64

template CPUArchitecture PEFile<CPUArchitecture::X64>::TryParseGeneralPeHeaders(ReadOnlyMemoryDataSource& ds, uint64_t offset,
	IMAGE_DOS_HEADER& dosHeader, IMAGE_FILE_HEADER& fileHeader);

template PEFile<CPUArchitecture::X64>::PEFile(ReadOnlyMemoryDataSource& ds, uint64_t offset);

template CPUArchitecture PEFile<CPUArchitecture::X64>::GetPeArch(ReadOnlyMemoryDataSource& ds, uint64_t offset);
