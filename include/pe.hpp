#pragma once

#include "memdatasource.hpp"

template <CPUArchitecture arch>
struct PEFileTraitsT
{
	typedef IMAGE_OPTIONAL_HEADER ImageOptionalHeaderT;
	typedef IMAGE_NT_HEADERS ImageNtHeadersT;
};

template <>
struct PEFileTraitsT<CPUArchitecture::X64>
{
	typedef IMAGE_OPTIONAL_HEADER64 ImageOptionalHeaderT;
	typedef IMAGE_NT_HEADERS64 ImageNtHeadersT;
};

template <CPUArchitecture arch = CPUArchitecture::X64>
class PEFile
{
public:
	typedef typename PEFileTraitsT<arch>::ImageNtHeadersT      ImageNtHeadersT;
	typedef typename PEFileTraitsT<arch>::ImageOptionalHeaderT ImageOptionalHeaderT;

	PEFile(ReadOnlyMemoryDataSource& ds, uint64_t offset);

	bool IsPeValid() const noexcept { return mIsPeValid; }

	static CPUArchitecture GetPeArch(ReadOnlyMemoryDataSource& ds, uint64_t offset);

	PEFile(const PEFile&) = delete;
	PEFile(PEFile&&) = delete;

	PEFile& operator = (const PEFile&) = delete;
	PEFile& operator = (PEFile&&) = delete;

protected:
	bool mIsPeValid;
	ReadOnlyMemoryDataSource& mDataSource;
	uint64_t mOffset;

	std::vector<IMAGE_SECTION_HEADER> mSections;

	static CPUArchitecture TryParseGeneralPeHeaders(ReadOnlyMemoryDataSource& ds, uint64_t offset,
		IMAGE_DOS_HEADER& dosHeader, IMAGE_FILE_HEADER& fileHeader);
};
