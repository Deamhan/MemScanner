#include "pe.hpp"

#include <algorithm>

template <CPUArchitecture arch>
CPUArchitecture MappedPEFile<arch>::TryParseGeneralPeHeaders(ReadOnlyMemoryDataSource& ds, uint64_t offset,
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

template <CPUArchitecture arch>
MappedPEFile<arch>::MappedPEFile(ReadOnlyMemoryDataSource& ds, uint64_t offset) : mDataSource(ds), mOffset(offset)
{
    try
    {
        IMAGE_DOS_HEADER dosHeader;
        IMAGE_FILE_HEADER fileHeader;
        auto peArch = TryParseGeneralPeHeaders(mDataSource, mOffset, dosHeader, fileHeader);
        if (peArch != arch)
            throw PeException{ PeError::InvalidFormat };

        ds.Read(mOptionalHeader);

        auto sectionsCount = std::min<size_t>(256, fileHeader.NumberOfSections);
        mSections.resize(sectionsCount);

        size_t read = 0;
        ds.Read(mSections.data(), mSections.size() * sizeof(IMAGE_SECTION_HEADER), read);
    }
    catch (const DataSourceException&)
    {
        throw PeException{ PeError::InvalidFormat };
    }
}

template <CPUArchitecture arch>
CPUArchitecture MappedPEFile<arch>::GetPeArch(ReadOnlyMemoryDataSource& ds, uint64_t offset)
{
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_FILE_HEADER fileHeader;
	return TryParseGeneralPeHeaders(ds, offset, dosHeader, fileHeader);
}

template <CPUArchitecture arch>
void MappedPEFile<arch>::BuildExportMap()
{
    try
    {
        uint32_t exportRva = mOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        uint32_t exportSize = mOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (exportRva == 0 || exportSize == 0)
            return;

        IMAGE_EXPORT_DIRECTORY Export;
        mDataSource.Read(exportRva + mOffset, Export);

        std::vector<uint32_t> rvaOfFunctions(std::min<uint32_t>(Export.NumberOfFunctions, 0x10000));
        std::vector<uint32_t> rvaOfNames(std::min<uint32_t>(Export.NumberOfNames, 0x10000));
        std::vector<uint16_t> Ordinals(std::min<uint32_t>(Export.NumberOfNames, 0x10000));

        size_t read = 0;
        if (rvaOfFunctions.size() != 0)
        {
            mDataSource.Read(Export.AddressOfFunctions + mOffset, &rvaOfFunctions[0],
                rvaOfFunctions.size() * sizeof(rvaOfFunctions[0]), read);
        }

        if (rvaOfNames.size() != 0)
        {
            mDataSource.Read(Export.AddressOfNames + mOffset, &rvaOfNames[0],
                rvaOfNames.size() * sizeof(rvaOfNames[0]), read);
        }

        if (Ordinals.size() != 0)
        {
            mDataSource.Read(Export.AddressOfNameOrdinals + mOffset, &Ordinals[0],
                Ordinals.size() * sizeof(Ordinals[0]), read);
        }

        for (size_t i = 0; i < rvaOfFunctions.size(); ++i)
        {
            std::pair<uint32_t, ExportedFunctionDescription> p;
            p.first = rvaOfFunctions[i];
            p.second.ordinal = (uint16_t)(i + Export.Base);
            if (p.first >= exportRva && p.first < exportRva + exportSize)
            {
                std::vector<char> buffer(0x100, '\0');
                mDataSource.Read(p.first + mOffset, &buffer[0], buffer.size(), read);
                p.second.forwardTarget = buffer.data();
            }

            mExport.insert(std::move(p));
        }

        for (size_t i = 0; i < Ordinals.size(); i++)
        {
            uint32_t ordinal = Ordinals[i];
            std::vector<char> buffer(0x100, '\0');
            mDataSource.Read(rvaOfNames[i] + mOffset, &buffer[0], buffer.size(), read);
            if (ordinal >= rvaOfFunctions.size())
                continue;

            auto exportedFunc = mExport.find(rvaOfFunctions[ordinal]);
            if (exportedFunc != mExport.end())
                exportedFunc->second.names.emplace_back(buffer.data());
        }
    }
    catch (const DataSourceException&)
    {
        throw PeException{ PeError::InvalidFormat };
    }
}

#if !_M_AMD64
template class MappedPEFile<CPUArchitecture::X86>;
#endif // !_M_AMD64

template class MappedPEFile<CPUArchitecture::X64>;
