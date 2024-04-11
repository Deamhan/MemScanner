#pragma once

#include "datasource.hpp"
#include "ntdll64.hpp"
#include "memhelper.hpp"

#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>

template <CPUArchitecture arch>
struct PeTraitsT
{
	typedef IMAGE_OPTIONAL_HEADER32 ImageOptionalHeaderT;
	typedef IMAGE_NT_HEADERS32 ImageNtHeadersT;
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

struct HookDescription
{
	std::shared_ptr<ExportedFunctionDescription> functionDescription;
	HookDescription(std::shared_ptr<ExportedFunctionDescription> funcDesc) : functionDescription(std::move(funcDesc)) {}
};

struct ImageModificationResult
{
	std::vector<HookDescription> hooksFound;
	bool headersModified;
	bool entryPointModified;

	bool IsModificationsFound() const noexcept
	{
		return !hooksFound.empty() || headersModified || entryPointModified;
	}
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

enum class RelocationType
{
	Absolute = 0,
	High = 1,
	Low = 2,
	HighLow = 3,
	HighAdj = 4,
	Dir64 = 10,
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
	uint64_t GetOriginalImageBase() const noexcept { return mOptionalHeader.ImageBase; }
	uint64_t GetLoadedImageBase() const noexcept { return mImageBase; }
	uint64_t GetExpectedImageBase() const noexcept { return isMapped ? GetLoadedImageBase() : GetOriginalImageBase(); }
	bool IsClrAssembly() const noexcept { return mOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0; }

	uint32_t GetEntryPointRVA() const noexcept { return mOptionalHeader.AddressOfEntryPoint; }

	PE(const PE&) = delete;
	PE(PE&&) = delete;

	PE& operator = (const PE&) = delete;
	PE& operator = (PE&&) = delete;

	uint32_t RvaToOffset(uint32_t rva, bool useTranslation = !isMapped) const;

	bool IsExecutableSectionRva(uint32_t rva) const;
	bool IsExecutableRange(uint32_t rva, uint32_t size) const;

	const std::map<uint32_t, std::shared_ptr<ExportedFunctionDescription>>& GetExportMap();
	std::shared_ptr<ExportedFunctionDescription> GetExportedFunction(uint32_t rva);

	void CheckForImageModification(DataSource& oppositeDs, ImageModificationResult& modificationCheckResult);

	void Dump(const wchar_t* path);

	void ReleaseDataSource() noexcept { mDataSource.reset(); }

	const std::map<uint32_t, RelocationType>& GetRelocations();

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
	void ParseRelocations();

	const unsigned MaxExportedFunctionsCount = 0x10000;
	std::unique_ptr<std::map<uint32_t, RelocationType>> mRelocations;
};

std::pair<uint64_t, CPUArchitecture> ScanRegionForPeHeaders(HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region);
bool ScanRegionForPeSections(HANDLE hProcess, const MemoryHelperBase::FlatMemoryMapT relatedRegions);
