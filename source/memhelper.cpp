#include "stdafx.h"

#include "../include/memhelper.hpp"

#include <algorithm>
#include <memory>

#include "../include/memdatasource.hpp"

using namespace SystemDefinitions;

void MemoryHelperBase::CloseHandleByPtr(HANDLE* handle)
{
    if (handle == nullptr || *handle == INVALID_HANDLE_VALUE || *handle == nullptr)
        return;

    CloseHandle(*handle);
}

void MemoryHelperBase::CloseSearchHandleByPtr(HANDLE* handle)
{
    if (*handle == INVALID_HANDLE_VALUE)
        return;

    FindClose(*handle);
}

bool MemoryHelperBase::EnableDebugPrivilege()
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    std::unique_ptr<HANDLE, void(*)(HANDLE*)> tokenGuard(&hToken, CloseHandleByPtr);
    LUID DebugValue = {};
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &DebugValue))
        return false;

    TOKEN_PRIVILEGES tkp;
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = DebugValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    return AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr) != FALSE;
}

template <CPUArchitecture arch>
thread_local std::vector<uint8_t> MemoryHelper<arch>::ImageNameBuffer(sizeof(UNICODE_STRING_T<PTR_T<arch>>) + 64 * 1024);

template <CPUArchitecture arch>
std::wstring MemoryHelper<arch>::GetImageNameByAddress(HANDLE hProcess, uint64_t address) const 
{
    auto ptr = (UNICODE_STRING_T<PTR_T<arch>>*)ImageNameBuffer.data();

    uint64_t retLen = 0;
    auto result = mApi.NtQueryVirtualMemory64(hProcess, address, MEMORY_INFORMATION_CLASS::MemorySectionName,
        ptr, ImageNameBuffer.size(), &retLen);

    if (!NtSuccess(result))
        return L"";

    std::wstring path = L"\\??\\GlobalRoot";
    path.append((const wchar_t*)ptr->Buffer, ptr->Length / sizeof(wchar_t));

    return path;
}

template <CPUArchitecture arch>
uint64_t MemoryHelper<arch>::GetHighestUsermodeAddress() const
{
    return 0xFFFFFFFFull; // LargeAddressAware option for 32 bit apps
}

template <>
uint64_t MemoryHelper<CPUArchitecture::X64>::GetHighestUsermodeAddress() const
{
    return 0x7FFFFFFFFFFFull;
}

template <CPUArchitecture arch>
static void ParseLoadedModules(const MemoryHelperBase& helper, uint64_t pebAddress, ReadOnlyMemoryDataSource& mds,
    std::vector<MemoryHelperBase::ImageDescription>& result, bool skipMainModule)
{
    try
    {
        PTR_T<arch> ldrPtr = 0;
        mds.Read(pebAddress + offsetof(PEB_T<PTR_T<arch>>, Ldr), ldrPtr);

        PEB_LDR_DATA_T<PTR_T<arch>> pebLdrData;
        mds.Read(ldrPtr, pebLdrData);

        auto rootEntry = ldrPtr + offsetof(PEB_LDR_DATA_T<PTR_T<arch>>, InLoadOrderModuleList);
        LDR_DATA_TABLE_ENTRY_T<PTR_T<arch>> ldrEntry;

        bool isMainImage = true;
        for (auto nextEntry = pebLdrData.InLoadOrderModuleList.Flink;
            nextEntry != rootEntry; nextEntry = ldrEntry.InLoadOrderLinks.Flink)
        {
            mds.Read(nextEntry, ldrEntry);
            // if WOW64 PEB is present so main image has x86 arch, not x64 - skip it for now
            if (arch == CPUArchitecture::X64 && skipMainModule && isMainImage)
            {
                isMainImage = false;
                continue;
            }

            // unreliable + manual WOW64 redirection is required
            /*std::wstring name(ldrEntry.FullDllName.Length / sizeof(WCHAR), L'\0');
            mds.Read(ldrEntry.FullDllName.Buffer, (void*)name.data(), name.size() * sizeof(WCHAR));*/

            result.emplace_back(ldrEntry.DllBase, PageAlignUp(ldrEntry.SizeOfImage), arch,
                helper.GetImageNameByAddress(mds.GetProcessHandle(), ldrEntry.DllBase));
        }
    }
    catch (const DataSourceException&)
    {
    }
}

template <CPUArchitecture arch>
std::vector<MemoryHelperBase::ImageDescription> MemoryHelper<arch>::GetImageDataFromPeb(HANDLE hProcess) const
{
    std::vector<MemoryHelperBase::ImageDescription> result;

    PROCESS_BASIC_INFORMATION<PTR_T<arch>> pbi = {};
    uint32_t retLength = 0;
    if (!NtSuccess(GetIWow64Helper().NtQueryInformationProcess64(hProcess, PROCESSINFOCLASS::ProcessBasicInformation,
        &pbi, sizeof(pbi), &retLength)))
        return result;

    uint64_t wow64peb = 0;
    GetIWow64Helper().NtQueryInformationProcess64(hProcess, PROCESSINFOCLASS::ProcessWow64Information,
        &wow64peb, sizeof(wow64peb), &retLength);

    ReadOnlyMemoryDataSource mds{ hProcess, 0, GetHighestUsermodeAddress(), 0 };

    ParseLoadedModules<arch>(*this, pbi.PebBaseAddressT, mds, result, wow64peb != 0);
    if (arch == CPUArchitecture::X86)
        return result;

    ParseLoadedModules<CPUArchitecture::X86>(*this, wow64peb, mds, result, false);

    return result;
}

template <CPUArchitecture arch>
MEMORY_BASIC_INFORMATION_T<uint64_t> MemoryHelper<arch>::ConvertToMemoryBasicInfo64(
    const MEMORY_BASIC_INFORMATION_T<PTR_T<arch>>& mbi)
{
    MEMORY_BASIC_INFORMATION_T<uint64_t> result;

    result.BaseAddress = mbi.BaseAddress;
    result.AllocationBase = mbi.AllocationBase;
    result.dummy1 = mbi.dummy1;
    result.RegionSize = mbi.RegionSize;
    result.State = mbi.State;
    result.Protect = mbi.Protect;
    result.dummy2 = mbi.dummy2;

    return result;
}

template <>
static MEMORY_BASIC_INFORMATION_T<uint64_t> MemoryHelper<CPUArchitecture::X64>::ConvertToMemoryBasicInfo64(
    const MEMORY_BASIC_INFORMATION_T<uint64_t>& mbi)
{
    return mbi;
}

template <CPUArchitecture arch>
bool MemoryHelper<arch>::GetBasicInfoByAddress(HANDLE hProcess, uint64_t address,
    MEMORY_BASIC_INFORMATION_T<uint64_t>& result) const
{
    MEMORY_BASIC_INFORMATION_T<PTR_T<arch>> mbi;
    if (!NtSuccess(mApi.NtQueryVirtualMemory64(hProcess, address, MEMORY_INFORMATION_CLASS::MemoryBasicInformation,
        &mbi, sizeof(mbi), nullptr)))
        return false;

    mbi.RegionSize = PageAlignUp(mbi.RegionSize);
    result = ConvertToMemoryBasicInfo64(mbi);

    return true;
}

template <CPUArchitecture arch>
MemoryHelperBase::MemInfoT64 MemoryHelper<arch>::UpdateMemoryMapForAddr(HANDLE hProcess, uint64_t addressToCheck,
    MemoryHelperBase::MemoryMapT& result, bool& isAllocationAligned) const
{
    MemInfoT64 primaryMbi, mbi;
    if (!GetBasicInfoByAddress(hProcess, addressToCheck, primaryMbi) || (primaryMbi.State & MEM_COMMIT) == 0)
        return {};

    MemInfoT64 retMbi = {};
    auto address = primaryMbi.AllocationBase;
    while (GetBasicInfoByAddress(hProcess, address, mbi) && mbi.AllocationBase == primaryMbi.AllocationBase)
    {
        if ((mbi.State & (MEM_COMMIT | MEM_RESERVE)) != 0)
            result.emplace(mbi.BaseAddress, mbi);

        if (retMbi.AllocationBase == 0 &&
            primaryMbi.BaseAddress + primaryMbi.RegionSize == mbi.BaseAddress + mbi.RegionSize)
            retMbi = mbi;

        address += std::max<uint64_t>(mbi.RegionSize, PAGE_SIZE);
    }

    isAllocationAligned = (address & 0xFFFF) == 0;

    return retMbi;
}

template <CPUArchitecture arch>
MemoryHelperBase::MemoryMapT MemoryHelper<arch>::GetMemoryMap(HANDLE hProcess) const 
{
    MemoryMapT result;
    uint64_t address = 0;
    MEMORY_BASIC_INFORMATION_T<uint64_t> mbi;
    while (GetBasicInfoByAddress(hProcess, address, mbi))
    {
        if ((mbi.State & (MEM_COMMIT | MEM_RESERVE)) != 0)           // reserved regions can help us to check if allocation was aligned or not (helps with .NET jitted code)
            result.emplace_hint(result.end(), mbi.BaseAddress, mbi); // every next address is higher than previous so must be pushed in the end of map with less comparer

        address += std::max<uint64_t>(mbi.RegionSize, PAGE_SIZE);
        if (address > GetHighestUsermodeAddress())
            break;
    }

    return result;
}

MemoryHelperBase::FlatMemoryMapT
    MemoryHelperBase::GetFlatMemoryMap(const MemoryHelperBase::MemoryMapT& mm,
    const std::function<bool(const MemoryHelperBase::MemInfoT64&)>& filter)
{
    FlatMemoryMapT result;
    for (const auto& infoKeyValue : mm)
    {
        if (!filter(infoKeyValue.second))
            continue;

        result.push_back(infoKeyValue.second);
    }

    return result;
}

bool MemoryHelperBase::IsAlignedAllocation(const MemoryHelperBase::FlatMemoryMapT& mm)
{
    if (mm.empty())
        return false;

    const auto& last = mm.back();
    return ((last.BaseAddress + last.RegionSize) & 0xFFFF) == 0;
}

bool MemoryHelperBase::IsReadableRegion(const MemInfoT64& region)
{
    return ((region.State & MEM_COMMIT) != 0 && (region.State & (PAGE_NOACCESS | PAGE_GUARD)) == 0);
}

uint64_t MemoryHelperBase::GetTopReadableBorder(const MemoryHelperBase::FlatMemoryMapT& mm)
{
    for (auto it = mm.rbegin(); it != mm.rend(); ++it)
    {
        const auto& region = *it;
        if (IsReadableRegion(region))
            return region.BaseAddress + region.RegionSize;
    }

    return 0;
}

MemoryHelperBase::GroupedMemoryMapT
MemoryHelperBase::GetGroupedMemoryMap(const MemoryHelperBase::MemoryMapT& mm,
    const std::function<bool(const MemoryHelperBase::MemInfoT64&)>& filter)
{
    GroupedMemoryMapT result;
    for (const auto& infoKeyValue : mm)
    {
        if (!filter(infoKeyValue.second))
            continue;

        auto iter = result.lower_bound(infoKeyValue.second.AllocationBase);
        if (iter != result.end() && iter->first == infoKeyValue.second.AllocationBase)
            iter->second.push_back(infoKeyValue.second);
        else
            result.emplace_hint(iter, infoKeyValue.second.AllocationBase, FlatMemoryMapT{ infoKeyValue.second });
    }

    return result;
}

uint32_t MemoryHelperBase::protToFlags(uint32_t prot)
{
    switch (prot & 0xff)
    {
    case PAGE_EXECUTE:
        return XFlag;
    case PAGE_EXECUTE_READ:
        return XFlag | RFlag;
    case PAGE_EXECUTE_READWRITE:
        return XFlag | RFlag | WFlag;
    case PAGE_EXECUTE_WRITECOPY:
        return XFlag | RFlag | WFlag;
    case PAGE_NOACCESS:
        return 0;
    case PAGE_READONLY:
        return RFlag;
    case PAGE_READWRITE:
        return RFlag | WFlag;
    case PAGE_WRITECOPY:
        return RFlag | WFlag;
    default:
        return XFlag | RFlag | WFlag;
    }
}


template <CPUArchitecture arch>
const MemoryHelper<arch>& GetMemoryHelperForArch()
{
    static MemoryHelper<arch> helper;
    return helper;
}

#if !_M_AMD64
template class MemoryHelper<CPUArchitecture::X86>;

template const MemoryHelper<CPUArchitecture::X86>& GetMemoryHelperForArch();
#endif// _M_AMD64

template class MemoryHelper<CPUArchitecture::X64>;

template const MemoryHelper<CPUArchitecture::X64>& GetMemoryHelperForArch();

const MemoryHelperBase& GetMemoryHelper() noexcept 
{ 
#if !_M_AMD64
    return GetOSArch() == CPUArchitecture::X64 ? (const MemoryHelperBase&)GetMemoryHelperForArch<CPUArchitecture::X64>()
        : (const MemoryHelperBase&)GetMemoryHelperForArch<CPUArchitecture::X86>();
#else
    return GetMemoryHelperForArch<CPUArchitecture::X64>();
#endif // !_M_AMD64
}
