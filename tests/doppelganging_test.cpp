#include <memory>

#include <Windows.h>
#include <ktmw32.h>

#include "system_defs.hpp"
#include "memhelper.hpp"

#pragma comment(lib, "KtmW32.lib")

using namespace SystemDefinitions;

typedef NT_STATUS (NTAPI * NtCreateSectionT)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    PVOID              ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
);

enum SECTION_INHERIT 
{
    ViewShare = 1,
    ViewUnmap = 2
};

typedef NT_STATUS (NTAPI * NtMapViewOfSectionT)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
);

typedef NT_STATUS (NTAPI* NtUnmapViewOfSectionT)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
);

auto hNtdll = GetModuleHandleW(L"ntdll");
auto NtCreateSection = (NtCreateSectionT)GetProcAddress(hNtdll, "NtCreateSection");
auto NtMapViewOfSection = (NtMapViewOfSectionT)GetProcAddress(hNtdll, "NtMapViewOfSection");
auto NtUnmapViewOfSection = (NtUnmapViewOfSectionT)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

PVOID MapSection(const wchar_t* newFileName, const void* data, DWORD dataSize)
{
    HANDLE hTransaction = CreateTransaction(nullptr, nullptr, 0, 0, 0, 0, nullptr);
    if (hTransaction == INVALID_HANDLE_VALUE) 
        return nullptr;
    
    std::unique_ptr<HANDLE, void(*)(HANDLE*)> transactionGuard(&hTransaction, MemoryHelperBase::CloseHandleByPtr);

    HANDLE hSection = nullptr;

    {
        HANDLE hNewFile = CreateFileTransactedW(newFileName, GENERIC_WRITE | GENERIC_READ, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr, hTransaction, nullptr, nullptr);

        if (hNewFile == INVALID_HANDLE_VALUE)
            return nullptr;

        std::unique_ptr<HANDLE, void(*)(HANDLE*)> newFileGuard(&hNewFile, MemoryHelperBase::CloseHandleByPtr);

        DWORD written = 0;
        if (WriteFile(hNewFile, data, dataSize, &written, nullptr) == FALSE)
            return nullptr;

        
        if (!NtSuccess(NtCreateSection(&hSection, SECTION_ALL_ACCESS, nullptr, 0, PAGE_READONLY, SEC_IMAGE, hNewFile)))
            return nullptr;
    }
    
    std::unique_ptr<HANDLE, void(*)(HANDLE*)> sectionGuard(&hSection, MemoryHelperBase::CloseHandleByPtr);
    if (RollbackTransaction(hTransaction) == FALSE)
        return nullptr;

    PVOID imageAddress = nullptr;
    SIZE_T viewSize = 0;
    if (!NtSuccess(NtMapViewOfSection(hSection, GetCurrentProcess(), &imageAddress,
        0, 0, nullptr, &viewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE)))
        return nullptr;

    return imageAddress;
}

std::vector<uint8_t> GetImageData()
{
    std::vector<uint8_t> result;

    WCHAR path[MAX_PATH];
    if (0 == GetModuleFileNameW(hNtdll, path, _countof(path)))
        return result;

    HANDLE hOriginalFile = CreateFileW(path,GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hOriginalFile == INVALID_HANDLE_VALUE)
        return result;

    std::unique_ptr<HANDLE, void(*)(HANDLE*)> newFileGuard(&hOriginalFile, MemoryHelperBase::CloseHandleByPtr);

    LARGE_INTEGER size = {};
    if (GetFileSizeEx(hOriginalFile, &size) == FALSE)
        return result;

    result.resize((size_t)size.QuadPart);
    DWORD read;
    if (ReadFile(hOriginalFile, result.data(), (DWORD)result.size(), &read, nullptr) == FALSE)
    {
        result.resize(0);
        return result;
    }

    return result;
}

bool TestMappedImage()
{
    auto data = GetImageData();
    if (data.empty())
        return false;

    std::wstring tmpFileName;
    tmpFileName.resize(MAX_PATH, L'\0');
    if (ExpandEnvironmentStringsW(L"%TMP%\\img.dll", (wchar_t*)tmpFileName.data(), (DWORD)tmpFileName.size()) == FALSE)
        return false;

    auto addr = MapSection(tmpFileName.c_str(), data.data(), (DWORD)data.size());
    auto unmapRoutine = [](PVOID addr) { NtUnmapViewOfSection(GetCurrentProcess(), addr); };
    std::unique_ptr<VOID, decltype(unmapRoutine)> mappingGuard(addr, unmapRoutine);

    NT_STATUS status;
    auto imagePath = GetMemoryHelper().GetImageNameByAddress(GetCurrentProcess(), (uintptr_t)addr, &status);
    return imagePath.empty() && status == NT_STATUS::StatusFileDeleted;
}

int main()
{
    return TestMappedImage() ? 0 : 1;
}
