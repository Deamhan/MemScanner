#pragma once

#include "memdatasource.hpp"

#include <list>
#include <map>
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
	std::string forwardTarget;
	uint32_t offset;

	uint8_t firstByte;
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
class PE
{
public:
	typedef typename PeTraitsT<arch>::ImageNtHeadersT      ImageNtHeadersT;
	typedef typename PeTraitsT<arch>::ImageOptionalHeaderT ImageOptionalHeaderT;

	PE(ReadOnlyDataSource& ds);

	static CPUArchitecture GetPeArch(ReadOnlyDataSource& ds);
	void BuildExportMap();

	uint32_t GetImageSize() const noexcept { return mOptionalHeader.SizeOfImage; }

	PE(const PE&) = delete;
	PE(PE&&) = delete;

	PE& operator = (const PE&) = delete;
	PE& operator = (PE&&) = delete;

	uint32_t RvaToOffset(uint32_t rva) const;

	bool IsExecutableSectionRva(uint32_t rva);

	const std::map<uint32_t, std::shared_ptr<ExportedFunctionDescription>>& GetExportMap() const noexcept { return mExportByRva; }

	std::vector<std::shared_ptr<ExportedFunctionDescription>> CheckExportForHooks(PE<false, arch>& imageOnDisk);

protected:
	ReadOnlyDataSource& mDataSource;

	ImageOptionalHeaderT mOptionalHeader;
	std::map<uint32_t, IMAGE_SECTION_HEADER> mSections;
	std::map<uint32_t, std::shared_ptr<ExportedFunctionDescription>> mExportByRva;

	static CPUArchitecture TryParseGeneralPeHeaders(ReadOnlyDataSource& ds, uint64_t offset,
		IMAGE_DOS_HEADER& dosHeader, IMAGE_FILE_HEADER& fileHeader);
};
