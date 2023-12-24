#include "file.hpp"
#include "memdatasource.hpp"
#include "memhelper.hpp"
#include "pe.hpp"

static std::wstring GetImageName(ReadOnlyMemoryDataSource& mapped)
{
	return GetMemoryHelper().GetImageNameByAddress(GetCurrentProcess(), mapped.GetOrigin());
}

template <CPUArchitecture arch>
static int CompareRelocs(std::shared_ptr<File> file, std::shared_ptr<ReadOnlyMemoryDataSource> mapped)
{
	try
	{
		PE<false, arch> peFile(file);
		PE<true, arch> peMapped(mapped);

		const auto& relocs = peFile.GetRelocations();
		auto originalImageBase = peFile.GetOriginalImageBase(),
			realImageBase = peMapped.GetLoadedImageBase();

		auto delta = realImageBase - originalImageBase;
		for (auto reloc : relocs)
		{
			if (!peFile.IsExecutableSectionRva(reloc.first))
				continue;

			typename PeTraitsT<arch>::PointerT ptrToCorrect;
			file->Read(peFile.RvaToOffset(reloc.first), ptrToCorrect);

			switch (reloc.second)
			{
			case RelocationType::Dir64:
				ptrToCorrect += delta;
				break;
			case RelocationType::HighLow:
				*(uint32_t*)&ptrToCorrect += (uint32_t)delta;
				break;
			case RelocationType::High:
				*(uint32_t*)&ptrToCorrect += HIWORD(delta);
				break;
			case RelocationType::Low:
				*(uint32_t*)&ptrToCorrect += LOWORD(delta);
				break;
			default:
				break;
			}

			typename PeTraitsT<arch>::PointerT ptrFromMappedImage;
			mapped->Read(reloc.first, ptrFromMappedImage);

			if (ptrFromMappedImage != ptrToCorrect)
				return 2;
		}

		return 0;
	}
	catch (const PeException&)
	{
		return 10;
	}
}

int main()
{
	auto moduleHandle = GetModuleHandleW(L"kernel32");
	if (moduleHandle == nullptr)
		return 1;

	auto moduleMapped = std::make_shared<ReadOnlyMemoryDataSource>(GetCurrentProcess(), (uintptr_t)moduleHandle, 100 * 1024 * 1024);
	auto moduleFile = std::make_shared<File>(GetImageName(*moduleMapped).c_str());

	switch (PE<>::GetPeArch(*moduleMapped))
	{
	case CPUArchitecture::X86:
		return CompareRelocs<CPUArchitecture::X86>(moduleFile, moduleMapped);
	case CPUArchitecture::X64:
		return CompareRelocs<CPUArchitecture::X64>(moduleFile, moduleMapped);

	default:
		return 3;
	}
}