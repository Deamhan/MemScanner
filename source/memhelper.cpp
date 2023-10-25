#include "memhelper.hpp"

#include <algorithm>
#include <memory>

template <CPUArchitecture arch>
void MemoryHelper<arch>::CloseHandleByPtr(HANDLE* handle)
{
    CloseHandle(*handle);
}

template <CPUArchitecture arch>
bool MemoryHelper<arch>::EnableDebugPrivilege()
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

    return AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
}

template <CPUArchitecture arch>
typename MemoryHelper<arch>::MemoryMapT MemoryHelper<arch>::GetMemoryMap(HANDLE hProcess, const Wow64Helper<arch>& api)
{
    MemoryMapT result;
    PTR_T<arch> address = 0;
    SystemDefinitions::MEMORY_BASIC_INFORMATION_T<PTR_T<arch>> mbi;
    while (NT_SUCCESS(api.NtQueryVirtualMemory64(hProcess, address, SystemDefinitions::MEMORY_INFORMATION_CLASS::MemoryBasicInformation,
        &mbi, sizeof(mbi), nullptr)))
    {
        if ((mbi.State & MEM_COMMIT) != 0)
            result.emplace(mbi.BaseAddress, mbi);

        auto prevAddr = address;
        address += std::max<PTR_T<arch>>(mbi.RegionSize, PAGE_SIZE);
        if (prevAddr > address)
            break;
    }

    return result;
}

template <CPUArchitecture arch>
typename MemoryHelper<arch>::FlatMemoryMapT
    MemoryHelper<arch>::GetFlatMemoryMap(const typename MemoryHelper<arch>::MemoryMapT& mm,
    const std::function<bool(const typename MemoryHelper<arch>::MemInfoT&)>& filter)
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

template <CPUArchitecture arch>
typename MemoryHelper<arch>::GroupedMemoryMapT
MemoryHelper<arch>::GetGroupedMemoryMap(const typename MemoryHelper<arch>::MemoryMapT& mm,
    const std::function<bool(const typename MemoryHelper<arch>::MemInfoT&)>& filter)
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

#if !_M_AMD64
template class MemoryHelper<CPUArchitecture::X86>;
#endif// _M_AMD64

template class MemoryHelper<CPUArchitecture::X64>;
