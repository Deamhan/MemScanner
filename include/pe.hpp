#pragma once

#include "memdatasource.hpp"

#include <list>
#include <map>
#include <string>

template <CPUArchitecture arch>
struct PEFileTraitsT
{
	typedef IMAGE_OPTIONAL_HEADER ImageOptionalHeaderT;
	typedef IMAGE_NT_HEADERS ImageNtHeadersT;
	typedef uint32_t PointerT;
};

template <>
struct PEFileTraitsT<CPUArchitecture::X64>
{
	typedef IMAGE_OPTIONAL_HEADER64 ImageOptionalHeaderT;
	typedef IMAGE_NT_HEADERS64 ImageNtHeadersT;
	typedef uint64_t PointerT;
};

struct ExportedFunctionDescription
{
	std::list<std::string> names;
	uint16_t ordinal;
	std::string forwardTarget;
	uint32_t rva;
};

enum class PeError
{
	InvalidFormat,
};

class PeException : public std::exception
{
public:
	PeException(PeError code, const char* message = "") : std::exception(message), mErrorCode(code)
	{}

	PeError GetErrorCode() const noexcept { return mErrorCode; }

protected:
	PeError mErrorCode;
};

template <CPUArchitecture arch = CPUArchitecture::X64>
class MappedPEFile
{
public:
	typedef typename PEFileTraitsT<arch>::ImageNtHeadersT      ImageNtHeadersT;
	typedef typename PEFileTraitsT<arch>::ImageOptionalHeaderT ImageOptionalHeaderT;

	MappedPEFile(ReadOnlyMemoryDataSource& ds, uint64_t offset);

	static CPUArchitecture GetPeArch(ReadOnlyMemoryDataSource& ds, uint64_t offset);

	void BuildExportMap();

	uint32_t GetImageSize() const noexcept { return mOptionalHeader.SizeOfImage; }

	MappedPEFile(const MappedPEFile&) = delete;
	MappedPEFile(MappedPEFile&&) = delete;

	MappedPEFile& operator = (const MappedPEFile&) = delete;
	MappedPEFile& operator = (MappedPEFile&&) = delete;

protected:
	ReadOnlyMemoryDataSource& mDataSource;
	uint64_t mOffset;

	ImageOptionalHeaderT mOptionalHeader;
	std::vector<IMAGE_SECTION_HEADER> mSections;
	std::map<uint32_t, ExportedFunctionDescription> mExport;

	static CPUArchitecture TryParseGeneralPeHeaders(ReadOnlyMemoryDataSource& ds, uint64_t offset,
		IMAGE_DOS_HEADER& dosHeader, IMAGE_FILE_HEADER& fileHeader);
};
