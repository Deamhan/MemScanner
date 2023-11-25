#include "memhelper.hpp"

#include <algorithm>
#include <memory>

using namespace SystemDefinitions;

void MemoryHelperBase::CloseHandleByPtr(HANDLE* handle)
{
    CloseHandle(*handle);
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
std::wstring MemoryHelper<arch>::GetImageNameByAddress(HANDLE hProcess, uint64_t address) const 
{
    std::vector<uint8_t> buffer(sizeof(UNICODE_STRING_T<PTR_T<arch>>) + 64 * 1024, L'\0');
    auto ptr = (UNICODE_STRING_T<PTR_T<arch>>*)buffer.data();

    uint64_t retLen = 0;
    auto result = mApi.NtQueryVirtualMemory64(hProcess, address, MEMORY_INFORMATION_CLASS::MemorySectionName,
        ptr, buffer.size(), &retLen);

    if (!NT_SUCCESS(result))
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
typename MemoryHelper<arch>::MemoryMapT MemoryHelper<arch>::GetMemoryMap(HANDLE hProcess) const 
{
    MemoryMapT result;
    PTR_T<arch> address = 0;
    MEMORY_BASIC_INFORMATION_T<PTR_T<arch>> mbi;
    while (NT_SUCCESS(mApi.NtQueryVirtualMemory64(hProcess, address, MEMORY_INFORMATION_CLASS::MemoryBasicInformation,
        &mbi, sizeof(mbi), nullptr)))
    {
        if ((mbi.State & MEM_COMMIT) != 0)
            result.emplace(mbi.BaseAddress, ConvertToMemoryBasicInfo64(mbi));

        auto prevAddr = address;
        address += std::max<PTR_T<arch>>(PageAlignUp(mbi.RegionSize), PAGE_SIZE);
        if (prevAddr > address)
            break;
    }

    return result;
}

template <CPUArchitecture arch>
bool MemoryHelper<arch>::GetBasicInfoByAddress(HANDLE hProcess, uint64_t address, 
    MEMORY_BASIC_INFORMATION_T<uint64_t>& result) const
{
    MEMORY_BASIC_INFORMATION_T<PTR_T<arch>> mbi;
    if (!NT_SUCCESS(mApi.NtQueryVirtualMemory64(hProcess, address, MEMORY_INFORMATION_CLASS::MemoryBasicInformation,
        &mbi, sizeof(mbi), nullptr)))
        return false;

    result = ConvertToMemoryBasicInfo64(mbi);
    return true;
}

typename MemoryHelperBase::FlatMemoryMapT
    MemoryHelperBase::GetFlatMemoryMap(const typename MemoryHelperBase::MemoryMapT& mm,
    const std::function<bool(const typename MemoryHelperBase::MemInfoT64&)>& filter)
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

typename MemoryHelperBase::GroupedMemoryMapT
MemoryHelperBase::GetGroupedMemoryMap(const typename MemoryHelperBase::MemoryMapT& mm,
    const std::function<bool(const typename MemoryHelperBase::MemInfoT64&)>& filter)
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
