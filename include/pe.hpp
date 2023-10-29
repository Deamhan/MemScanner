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
	uint32_t offset;
};

enum class PeError
{
	InvalidFormat,
	InvalidRva,
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

template <bool isMapped = true, CPUArchitecture arch = CPUArchitecture::X64>
class PEFile
{
public:
	typedef typename PEFileTraitsT<arch>::ImageNtHeadersT      ImageNtHeadersT;
	typedef typename PEFileTraitsT<arch>::ImageOptionalHeaderT ImageOptionalHeaderT;

	PEFile(ReadOnlyDataSource& ds);

	static CPUArchitecture GetPeArch(ReadOnlyDataSource& ds);
	void BuildExportMap();

	uint32_t GetImageSize() const noexcept { return mOptionalHeader.SizeOfImage; }

	PEFile(const PEFile&) = delete;
	PEFile(PEFile&&) = delete;

	PEFile& operator = (const PEFile&) = delete;
	PEFile& operator = (PEFile&&) = delete;

	uint32_t RvaToOffset(uint32_t rva) const;

	const std::map<uint32_t, ExportedFunctionDescription>& GetExportMap() const noexcept { return mExport; }

protected:
	ReadOnlyDataSource& mDataSource;

	ImageOptionalHeaderT mOptionalHeader;
	std::map<uint32_t, IMAGE_SECTION_HEADER> mSections;
	std::map<uint32_t, ExportedFunctionDescription> mExport;

	static CPUArchitecture TryParseGeneralPeHeaders(ReadOnlyDataSource& ds, uint64_t offset,
		IMAGE_DOS_HEADER& dosHeader, IMAGE_FILE_HEADER& fileHeader);

};
