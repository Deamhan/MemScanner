#include "pe.hpp"

#include <algorithm>

template <bool isMapped, CPUArchitecture arch>
CPUArchitecture PEFile<isMapped, arch>::TryParseGeneralPeHeaders(ReadOnlyDataSource& ds, uint64_t offset,
	IMAGE_DOS_HEADER& dosHeader, IMAGE_FILE_HEADER& fileHeader)
{
    try
    {
        ds.Seek(offset);
        ds.Read(dosHeader);

        if (dosHeader.e_magic != 0x5a4d)
            return CPUArchitecture::Unknown;

        ds.Seek(dosHeader.e_lfanew + offset);
        DWORD signature = 0;
        ds.Read(signature);
        if (signature != 0x4550)
            return CPUArchitecture::Unknown;

        ds.Read(fileHeader);

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
    catch (const DataSourceException&)
    {
        return CPUArchitecture::Unknown;
    }
}

template <bool isMapped, CPUArchitecture arch>
PEFile<isMapped, arch>::PEFile(ReadOnlyDataSource& ds) : mDataSource(ds)
{
    try
    {
        IMAGE_DOS_HEADER dosHeader;
        IMAGE_FILE_HEADER fileHeader;
        auto peArch = TryParseGeneralPeHeaders(mDataSource, 0, dosHeader, fileHeader);
        if (peArch != arch)
            throw PeException{ PeError::InvalidFormat };

        ds.Read(mOptionalHeader);

        auto sectionsCount = std::min<size_t>(256, fileHeader.NumberOfSections);

        for (size_t i = 0; i < sectionsCount; ++i)
        {
            IMAGE_SECTION_HEADER header;
            ds.Read(header);

            mSections.emplace(header.VirtualAddress + PageAlignUp(header.Misc.VirtualSize), header);
        }
    }
    catch (const DataSourceException&)
    {
        throw PeException{ PeError::InvalidFormat };
    }
}

template <bool isMapped, CPUArchitecture arch>
CPUArchitecture PEFile<isMapped, arch>::GetPeArch(ReadOnlyDataSource& ds)
{
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_FILE_HEADER fileHeader;
	return TryParseGeneralPeHeaders(ds, 0, dosHeader, fileHeader);
}

template <bool isMapped, CPUArchitecture arch>
void PEFile<isMapped, arch>::BuildExportMap()
{
    try
    {
        uint32_t exportRva = mOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        uint32_t exportSize = mOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (exportRva == 0 || exportSize == 0)
            return;

        IMAGE_EXPORT_DIRECTORY Export;
        auto exportOffset = RvaToOffset(exportRva);
        mDataSource.Read(exportOffset, Export);

        std::vector<uint32_t> functions(std::min<uint32_t>(Export.NumberOfFunctions, 0x10000));
        std::vector<uint32_t> names(std::min<uint32_t>(Export.NumberOfNames, 0x10000));
        std::vector<uint16_t> ordinals(std::min<uint32_t>(Export.NumberOfNames, 0x10000));

        auto rvaToOffsetFunc = [this](uint32_t rva) { return RvaToOffset(rva); };

        if (functions.size() != 0)
        {
            mDataSource.Read(RvaToOffset(Export.AddressOfFunctions), &functions[0],
                functions.size() * sizeof(functions[0]));

            std::transform(functions.begin(), functions.end(), functions.begin(),
                rvaToOffsetFunc);
        }

        if (names.size() != 0)
        {
            mDataSource.Read(RvaToOffset(Export.AddressOfNames), &names[0],
                names.size() * sizeof(names[0]));

            std::transform(names.begin(), names.end(), names.begin(),
                rvaToOffsetFunc);
        }

        if (ordinals.size() != 0)
        {
            mDataSource.Read(RvaToOffset(Export.AddressOfNameOrdinals), &ordinals[0],
                ordinals.size() * sizeof(ordinals[0]));
        }

        for (size_t i = 0; i < functions.size(); ++i)
        {
            std::pair<uint32_t, ExportedFunctionDescription> p;
            p.first = functions[i];
            p.second.ordinal = (uint16_t)(i + Export.Base);
            if (p.first >= exportOffset && p.first < exportOffset + exportSize)
            {
                std::vector<char> buffer(0x100, '\0');
                mDataSource.Read(p.first, &buffer[0], buffer.size());
                p.second.forwardTarget = buffer.data();
                p.second.offset = 0;
            }
            else
                p.second.offset = p.first;

            mExport.insert(std::move(p));
        }

        for (size_t i = 0; i < ordinals.size(); i++)
        {
            uint32_t ordinal = ordinals[i];
            std::vector<char> buffer(0x100, '\0');
            mDataSource.Read(names[i], &buffer[0], buffer.size());
            if (ordinal >= functions.size())
                continue;

            auto exportedFunc = mExport.find(functions[ordinal]);
            if (exportedFunc != mExport.end())
                exportedFunc->second.names.emplace_back(buffer.data());
        }
    }
    catch (const DataSourceException&)
    {
        throw PeException{ PeError::InvalidFormat };
    }
}

template <bool isMapped, CPUArchitecture arch>
uint32_t PEFile<isMapped, arch>::RvaToOffset(uint32_t rva) const
{
    if (isMapped)
        return rva;

    auto iter = mSections.upper_bound(rva);
    if (rva >= iter->second.VirtualAddress)
        return iter->second.PointerToRawData + (rva - iter->second.VirtualAddress);

    if (!mSections.empty() && mSections.begin()->second.VirtualAddress > rva)
        return rva;

    throw PeException{ PeError::InvalidRva };
}

#if !_M_AMD64
template class PEFile<false, CPUArchitecture::X86>;
template class PEFile<true, CPUArchitecture::X86>;
#endif // !_M_AMD64

template class PEFile<false, CPUArchitecture::X64>;
template class PEFile<true, CPUArchitecture::X64>;
