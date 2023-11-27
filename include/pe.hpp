#pragma once

#include "datasource.hpp"
#include "ntdll64.hpp"

#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>

template <CPUArchitecture arch>
struct PeTraitsT
{
	typedef IMAGE_OPTIONAL_HEADER ImageOptionalHeaderT;
	typedef IMAGE_NT_HEADERS ImageNtHeadersT;
	typedef uint32_t PointerT;
};

template <>
struct PeTraitsT<CPUArchitecture::X64>
{
	typedef IMAGE_OPTIONAL_HEADER64 ImageOptionalHeaderT;
	typedef IMAGE_NT_HEADERS64 ImageNtHeadersT;
	typedef uint64_t PointerT;
};

struct ExportedFunctionDescription
{
	std::list<std::string> names;
	uint16_t ordinal;
	uint32_t offset;
	uint32_t rva;

	uint8_t firstByte;
};

enum class PeError
{
	InvalidFormat,
	InvalidRva,
	FailedToDump,
	InvalidDataSource
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
class PE
{
public:
	typedef typename PeTraitsT<arch>::ImageNtHeadersT      ImageNtHeadersT;
	typedef typename PeTraitsT<arch>::ImageOptionalHeaderT ImageOptionalHeaderT;
	typedef typename PeTraitsT<arch>::PointerT             PointerT;

	PE(std::shared_ptr<DataSource> ds);

	static CPUArchitecture GetPeArch(DataSource& ds);

	uint32_t GetImageSize() const noexcept { return mOptionalHeader.SizeOfImage; }
	uint64_t GetImageBase() const noexcept { return mImageBase; }

	PE(const PE&) = delete;
	PE(PE&&) = delete;

	PE& operator = (const PE&) = delete;
	PE& operator = (PE&&) = delete;

	uint32_t RvaToOffset(uint32_t rva, bool useTranslation = !isMapped) const;

	bool IsExecutableSectionRva(uint32_t rva);

	const std::map<uint32_t, std::shared_ptr<ExportedFunctionDescription>>& GetExportMap();

	void CheckExportForHooks(DataSource& oppositeDs, std::vector<std::shared_ptr<ExportedFunctionDescription>>& result);

	void Dump(const wchar_t* path);

	void ReleaseDataSource() noexcept { mDataSource.reset(); }

protected:
	std::shared_ptr<DataSource> mDataSource;

	uint64_t mImageBase;
	IMAGE_DOS_HEADER mDosHeader;
	IMAGE_FILE_HEADER mFileHeader;
	ImageOptionalHeaderT mOptionalHeader;
	std::map<uint32_t, IMAGE_SECTION_HEADER> mSections;
	std::unique_ptr<std::map<uint32_t, std::shared_ptr<ExportedFunctionDescription>>> mExportByRva;

	const size_t MaxSectionsCount = 256;

	static CPUArchitecture TryParseGeneralPeHeaders(DataSource& ds, uint64_t offset,
		IMAGE_DOS_HEADER& dosHeader, IMAGE_FILE_HEADER& fileHeader);

	void BuildExportMap();

	const unsigned MaxExportedFunctionsCount = 0x10000;
};
