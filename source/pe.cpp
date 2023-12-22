#include "pe.hpp"

#include "file.hpp"
#include "memdatasource.hpp"
#include "memhelper.hpp"

#include <algorithm>

const uint16_t MzMagic = 0x5a4d;
const uint32_t PeMagic = 0x4550;

template <bool isMapped, CPUArchitecture arch>
CPUArchitecture PE<isMapped, arch>::TryParseGeneralPeHeaders(DataSource& ds, uint64_t offset,
	IMAGE_DOS_HEADER& dosHeader, IMAGE_FILE_HEADER& fileHeader)
{
    try
    {
        ds.Read(offset, dosHeader);
        if (dosHeader.e_magic != MzMagic)
            return CPUArchitecture::Unknown;

        DWORD signature = 0;
        ds.Read(dosHeader.e_lfanew + offset, signature);
        if (signature != PeMagic)
            return CPUArchitecture::Unknown;

        ds.Read(fileHeader);

        switch (fileHeader.Machine)
        {
        case IMAGE_FILE_MACHINE_I386:
            return CPUArchitecture::X86;
        case IMAGE_FILE_MACHINE_AMD64:
            return CPUArchitecture::X64;
        default:
            return CPUArchitecture::Unknown;
        }
    }
    catch (const DataSourceException&)
    {
        return CPUArchitecture::Unknown;
    }
}

template <bool isMapped, CPUArchitecture arch>
PE<isMapped, arch>::PE(std::shared_ptr<DataSource> ds) : mDataSource(std::move(ds))
{
    if (!mDataSource)
        throw PeException{ PeError::InvalidDataSource };

    try
    {
        mImageBase = mDataSource->GetOrigin();

        auto peArch = TryParseGeneralPeHeaders(*mDataSource, 0, mDosHeader, mFileHeader);
        if (peArch != arch)
            throw PeException{ PeError::InvalidFormat };

        mDataSource->Read(mOptionalHeader);

        auto sectionsCount = std::min<size_t>(MaxSectionsCount, mFileHeader.NumberOfSections);

        for (size_t i = 0; i < sectionsCount; ++i)
        {
            IMAGE_SECTION_HEADER header;
            mDataSource->Read(header);

            mSections.emplace(header.VirtualAddress + PageAlignUp(header.Misc.VirtualSize), header);
        }
    }
    catch (const DataSourceException&)
    {
        throw PeException{ PeError::InvalidFormat };
    }
}

template <bool isMapped, CPUArchitecture arch>
CPUArchitecture PE<isMapped, arch>::GetPeArch(DataSource& ds)
{
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_FILE_HEADER fileHeader;
	return TryParseGeneralPeHeaders(ds, 0, dosHeader, fileHeader);
}

template <bool isMapped, CPUArchitecture arch>
void PE<isMapped, arch>::BuildExportMap()
{
    if (!mDataSource)
        throw PeException{ PeError::InvalidDataSource };

    try
    {
        mExportByRva = std::make_unique<std::map<uint32_t, std::shared_ptr<ExportedFunctionDescription>>>();

        uint32_t exportRva = mOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        uint32_t exportSize = mOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (exportRva == 0 || exportSize == 0)
            return;

        IMAGE_EXPORT_DIRECTORY Export;
        auto exportOffset = RvaToOffset(exportRva);
        mDataSource->Read(exportOffset, Export);

        std::vector<uint32_t> functions(std::min<uint32_t>(Export.NumberOfFunctions, MaxExportedFunctionsCount));
        std::vector<uint32_t> names(std::min<uint32_t>(Export.NumberOfNames, MaxExportedFunctionsCount));
        std::vector<uint16_t> ordinals(std::min<uint32_t>(Export.NumberOfNames, MaxExportedFunctionsCount));

        auto rvaToOffsetFunc = [this](uint32_t rva) { return RvaToOffset(rva); };

        if (functions.size() != 0)
        {
            mDataSource->Read(RvaToOffset(Export.AddressOfFunctions), &functions[0],
                functions.size() * sizeof(functions[0]));
        }

        if (names.size() != 0)
        {
            mDataSource->Read(RvaToOffset(Export.AddressOfNames), &names[0],
                names.size() * sizeof(names[0]));

            std::transform(names.begin(), names.end(), names.begin(),
                rvaToOffsetFunc);
        }

        if (ordinals.size() != 0)
        {
            mDataSource->Read(RvaToOffset(Export.AddressOfNameOrdinals), &ordinals[0],
                ordinals.size() * sizeof(ordinals[0]));
        }

        for (size_t i = 0; i < functions.size(); ++i)
        {
            auto functionRva = functions[i];
            if (functionRva >= exportRva && functionRva < exportRva + exportSize)
                continue;

            if (!IsExecutableSectionRva(functionRva))
                continue;

            std::pair<uint32_t, std::shared_ptr<ExportedFunctionDescription>> p{ functions[i], std::make_unique<ExportedFunctionDescription>() };
            p.second->ordinal = (uint16_t)(i + Export.Base);
            p.second->offset = RvaToOffset(p.first);
            p.second->rva = p.first;

            mExportByRva->insert(std::move(p));
        }

        for (size_t i = 0; i < ordinals.size(); i++)
        {
            uint32_t ordinal = ordinals[i];
            std::vector<char> buffer(0x100, '\0');
            mDataSource->Read(names[i], &buffer[0], buffer.size());
            if (ordinal >= functions.size())
                continue;

            auto exportedFunc = mExportByRva->find(functions[ordinal]);
            if (exportedFunc != mExportByRva->end())
                exportedFunc->second->names.emplace_back(buffer.data());
        }

        for (auto& exportedFunc : *mExportByRva)
            mDataSource->Read(exportedFunc.second->offset, exportedFunc.second->firstByte);
    }
    catch (const DataSourceException&)
    {
        throw PeException{ PeError::InvalidFormat };
    }
}

template <bool isMapped, CPUArchitecture arch>
const std::map<uint32_t, std::shared_ptr<ExportedFunctionDescription>>& PE<isMapped, arch>::GetExportMap() 
{ 
    if (!mExportByRva)
        BuildExportMap();

    return *mExportByRva; 
}

template <bool isMapped, CPUArchitecture arch>
std::shared_ptr<ExportedFunctionDescription> PE<isMapped, arch>::GetExportedFunction(uint32_t rva)
{
    if (!mExportByRva)
        BuildExportMap();

    auto it = mExportByRva->find(rva);
    if (it == mExportByRva->end())
        return std::shared_ptr<ExportedFunctionDescription>{};

    return it->second;
}

template <bool isMapped, CPUArchitecture arch>
uint32_t PE<isMapped, arch>::RvaToOffset(uint32_t rva, bool useTranslation) const
{
    if (!useTranslation)
        return rva;

    auto iter = mSections.upper_bound(rva);
    if (iter == mSections.end())
        throw PeException{ PeError::InvalidRva };

    if (rva >= iter->second.VirtualAddress)
        return iter->second.PointerToRawData + (rva - iter->second.VirtualAddress);

    if (!mSections.empty() && mSections.begin()->second.VirtualAddress > rva)
        return rva;

    throw PeException{ PeError::InvalidRva };
}

template <bool isMapped, CPUArchitecture arch>
bool PE<isMapped, arch>::IsExecutableSectionRva(uint32_t rva)
{
    auto iter = mSections.upper_bound(rva);
    if (iter != mSections.end() && rva >= iter->second.VirtualAddress)
        return (iter->second.Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0;

    return false;
}

template <bool isMapped, CPUArchitecture arch>
void PE<isMapped, arch>::CheckExportForHooks(DataSource& oppositeDs, std::vector<HookDescription>& result)
{
    const auto& exportMap = GetExportMap();
    try
    {
        result.clear();

        for (const auto& exportedFunc : exportMap)
        {
            uint8_t oppositeDsData = 0;
            oppositeDs.Read(RvaToOffset(exportedFunc.first, isMapped), oppositeDsData); // is this is mapped PE so oppositeDs point to file/fragment and translation is required and vice versa
            if (oppositeDsData != exportedFunc.second->firstByte)
                result.push_back(exportedFunc.second);  
        }
    }
    catch (const DataSourceException&)
    {
        throw PeException(PeError::InvalidRva);
    }
}

template <bool isMapped, CPUArchitecture arch>
void PE<isMapped, arch>::Dump(const wchar_t* path)
{
    if (!mDataSource)
        throw PeException{ PeError::InvalidDataSource };

    const size_t MaxAllowedPeHeaderOffset = 1024 * 1024;
    const size_t MaxImageSize = 256 * 1024 * 1024;

    if (mOptionalHeader.SizeOfImage > MaxImageSize)
        throw PeException{ PeError::FailedToDump, "Too big image" };

    if (mDosHeader.e_lfanew > MaxAllowedPeHeaderOffset)
        throw PeException{ PeError::FailedToDump, "Too high PE header offset" };

    if (mFileHeader.NumberOfSections > MaxSectionsCount)
        throw PeException{ PeError::FailedToDump, "Too many sections" };

    File dump(path, File::CreateNew);

    std::vector<uint8_t> buffer(MaxAllowedPeHeaderOffset);
    mDataSource->Read(0, buffer.data(), mDosHeader.e_lfanew);
    dump.Write(buffer.data(), mDosHeader.e_lfanew);
    dump.Write(uint32_t(0x4550));
    dump.Write(mFileHeader);

    ImageOptionalHeaderT fixedImageHeader = mOptionalHeader;
    fixedImageHeader.ImageBase = (PointerT)mImageBase;
    dump.Write(fixedImageHeader);

    auto sectionsCount = std::min<size_t>(MaxSectionsCount, mFileHeader.NumberOfSections);

    mDataSource->Seek(mDosHeader.e_lfanew + sizeof(ImageNtHeadersT));
    for (size_t i = 0; i < sectionsCount; ++i)
    {
        IMAGE_SECTION_HEADER header;
        mDataSource->Read(header);
        header.PointerToRawData = header.VirtualAddress;
        dump.Write(header);
    }

    auto currentPos = mDataSource->GetOffset();
    auto alignedPos = PageAlignUp(currentPos);
    auto alignment = (size_t)(alignedPos - currentPos);
    if (alignment != 0)
    {
        mDataSource->Read(buffer.data(), alignment);
        dump.Write(buffer.data(), alignment);
    }

    // dump PE page by page, use zero filling on failure
    std::vector<uint8_t> zeroPage(PAGE_SIZE, 0);
    auto alignedImageSize = PageAlignUp(mOptionalHeader.SizeOfImage);
    while (alignedImageSize > alignedPos)
    {
        auto bufferPtr = buffer.data();
        try
        {
            mDataSource->Read(alignedPos, buffer.data(), PAGE_SIZE);
        }
        catch (const DataSourceException&)
        {
            bufferPtr = zeroPage.data();
        }

        alignedPos += PAGE_SIZE;
        dump.Write(bufferPtr, PAGE_SIZE);
    }
}

template class PE<false, CPUArchitecture::X86>;
template class PE<true, CPUArchitecture::X86>;

template class PE<false, CPUArchitecture::X64>;
template class PE<true, CPUArchitecture::X64>;


static size_t ScanBlobForMz(const std::vector<uint8_t>& buffer, size_t offset, size_t size)
{
    for (size_t i = offset; i < size - 1; ++i)
    {
        if (*(uint16_t*)(buffer.data() + i) == MzMagic)
            return i;
    }

    return size;
}

std::pair<uint64_t, CPUArchitecture> ScanRegionForPeHeaders(HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region)
{
    ReadOnlyMemoryDataSource memory(hProcess, region.BaseAddress, region.RegionSize);
    std::vector<uint8_t> buffer(64 * 1024);
    for (uint64_t offs = 0; offs < region.RegionSize; offs += buffer.size())
    {
        try
        {
            auto read = (size_t)std::min<uint64_t>(buffer.size(), region.RegionSize - offs);
            memory.Read(offs, buffer.data(), read);
            size_t mzPos = ScanBlobForMz(buffer, 0, read);
            if (mzPos == read)
                break;

            DataSourceFragment fragment(memory, mzPos);
            auto arch = PE<>::GetPeArch(fragment);
            if (arch != CPUArchitecture::Unknown)
                return  { fragment.GetOrigin(), arch };
        }
        catch (const DataSourceException&)
        {
        }
    }

    return { 0, CPUArchitecture::Unknown };
}

static bool IsSectionBorder(const uint8_t* buffer, size_t size)
{
    for (size_t i = 0; i < size / 2; ++i)
    {
        if (buffer[i] != 0)
            return false;
    }

    size_t counter = 0;
    for (size_t i = size / 2; i < size; ++i)
    {
        if (buffer[i] != 0)
            ++counter;
    }

    return counter * 4 >= size;
}

bool ScanRegionForPeSections(HANDLE hProcess, const MemoryHelperBase::FlatMemoryMapT relatedRegions)
{
    if (relatedRegions.empty())
        return false;

    auto last = relatedRegions.rbegin();
    auto begin = relatedRegions.begin()->BaseAddress, end = last->BaseAddress + last->RegionSize;
    auto size = end - begin;

    if (size < 16 * PAGE_SIZE)
        return false;

    ReadOnlyMemoryDataSource ds(hProcess, begin, size, 0);
    uint8_t buffer[64];
    size_t borders = 0;

    for (int offset = PAGE_SIZE - sizeof(buffer) / 2; offset + sizeof(buffer) / 2 <= size; offset += PAGE_SIZE)
    {
        try
        {
            ds.Read(offset, buffer, sizeof(buffer));
            if (IsSectionBorder(buffer, sizeof(buffer)))
                ++borders;
        }
        catch (const DataSourceException&)
        {
        }
    }

    if (borders == 0)
        return false;

    return size / borders > 4 * PAGE_SIZE;
}
