#include <memory>

#include "system_defs.hpp"
#include "memhelper.hpp"

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

bool TestMappedImage()
{
    auto hNtdll = GetModuleHandleW(L"ntdll");
    auto NtCreateSection = (NtCreateSectionT)GetProcAddress(hNtdll, "NtCreateSection");
    auto NtMapViewOfSection = (NtMapViewOfSectionT)GetProcAddress(hNtdll, "NtMapViewOfSection");
    auto NtUnmapViewOfSection = (NtUnmapViewOfSectionT)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    WCHAR path[MAX_PATH];
    if (0 == GetModuleFileNameW(hNtdll, path, _countof(path)))
        return false;

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    std::unique_ptr<HANDLE, void(*)(HANDLE*)> fileHandleGuard(&hFile, MemoryHelperBase::CloseHandleByPtr);

    HANDLE hSection = nullptr;
    if (!NtSuccess(NtCreateSection(&hSection, SECTION_ALL_ACCESS, nullptr, nullptr, PAGE_READONLY, SEC_IMAGE, hFile)))
        return false;

    std::unique_ptr<HANDLE, void(*)(HANDLE*)> sectionHandleGuard(&hSection, MemoryHelperBase::CloseHandleByPtr);

    PVOID imageAddress = nullptr;
    SIZE_T viewSize = 0;
    if (!NtSuccess(NtMapViewOfSection(hSection, GetCurrentProcess(), &imageAddress,
        0, 0, nullptr, &viewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE)))
        return false;

    auto unmapRoutine = [NtUnmapViewOfSection](PVOID addr) { NtUnmapViewOfSection(GetCurrentProcess(), addr); };
    std::unique_ptr<VOID, decltype(unmapRoutine)> mappingGuard(imageAddress, unmapRoutine);

    bool found = false;
    const auto& helper = GetMemoryHelper();
    return helper.IsModuleKnownByPeb(GetCurrentProcess(), (uintptr_t)imageAddress, found) && !found;
}

int main()
{
    const auto& helper = GetMemoryHelper();
    auto addr = (uintptr_t)GetModuleHandleW(L"ntdll");

    bool found = false;
    if (!helper.IsModuleKnownByPeb(GetCurrentProcess(), addr + 0x1000, found))
        return 1;

    if (!found)
        return 2;

    return TestMappedImage() ? 0 : 3;
}
