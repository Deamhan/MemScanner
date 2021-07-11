#include "ntdll64.h"

#include <memory>

using namespace SystemDefinitions;

#if !_X64_
extern "C" NT_STATUS X64Function(uint64_t Func, uint32_t Argc, uint64_t Arg0, uint64_t Arg1, uint64_t Arg2, uint64_t Arg3, ...);
extern "C" void MemCpy(void* pDest, uint64_t pSource, uint32_t size);
extern "C" int  MemCmp(const void* pDest, uint64_t pSource, uint32_t size);
extern "C" void GetTEB64(uint64_t * pTeb64);
#endif // !_X64_

#define SURE(f) if ((f) == 0) return

template <CPUArchitecture arch>
const Wow64Helper<arch>& GetWow64Helper()
{ 
    static Wow64Helper<arch> api;
    return api;
}

template const Wow64Helper<CPUArchitecture::X64>& GetWow64Helper();
#if !_X64_
template const Wow64Helper<CPUArchitecture::X86>& GetWow64Helper();
#endif // _X64_

template <CPUArchitecture arch>
Wow64Helper<arch>::Wow64Helper() : m_isOk(false)
{
    SURE(m_Ntdll = GetModuleHandle64(L"ntdll.dll"));
    SURE(m_LdrGetProcedureAddress = getLdrGetProcedureAddress());
    SURE(m_NtQueryVirtualMemory = GetProcAddress64(m_Ntdll, "NtQueryVirtualMemory"));
    SURE(m_NtAllocateVirtualMemory = GetProcAddress64(m_Ntdll, "NtAllocateVirtualMemory"));
    SURE(m_NtFreeVirtualMemory = GetProcAddress64(m_Ntdll, "NtFreeVirtualMemory"));
    SURE(m_NtReadVirtualMemory = GetProcAddress64(m_Ntdll, "NtReadVirtualMemory"));
    SURE(m_NtWriteVirtualMemory = GetProcAddress64(m_Ntdll, "NtWriteVirtualMemory"));
    SURE(m_NtGetContextThread = GetProcAddress64(m_Ntdll,   "NtGetContextThread"));
    SURE(m_NtSetContextThread = GetProcAddress64(m_Ntdll,   "NtSetContextThread"));
    SURE(m_NtQueryInformationProcess = GetProcAddress64(m_Ntdll, "NtQueryInformationProcess"));
    SURE(m_NtQueryInformationThread  = GetProcAddress64(m_Ntdll, "NtQueryInformationThread"));
    SURE(m_NtQuerySystemInformation  = GetProcAddress64(m_Ntdll, "NtQuerySystemInformation"));

    m_isOk = true;
}

template <CPUArchitecture arch>
HMODULE_T<arch> Wow64Helper<arch>::GetModuleHandle64(const wchar_t* lpModuleName) const noexcept
{
    return ::GetModuleHandleW(lpModuleName);
}

template <CPUArchitecture arch>
FARPROC_T<arch> Wow64Helper<arch>::GetProcAddress64(HMODULE_T<arch> hModule, const char* funcName) const noexcept
{
    return GetProcAddress(hModule, funcName);
}

template <CPUArchitecture arch>
FARPROC_T<arch> Wow64Helper<arch>::getLdrGetProcedureAddress()
{
    return GetProcAddress(m_Ntdll, "LdrGetProcedureAddress");
}

#if !_X64_
template <>
HMODULE_T<CPUArchitecture::X64> Wow64Helper<CPUArchitecture::X64>::GetModuleHandle64(const wchar_t* lpModuleName) const noexcept
{
    TEB64 teb64;
    uint64_t pTeb64 = 0;
    GetTEB64(&pTeb64);
    MemCpy(&teb64, pTeb64, sizeof(TEB64));

    PEB64 peb64;
    MemCpy(&peb64, teb64.ProcessEnvironmentBlock, sizeof(PEB64));
    PEB_LDR_DATA64 ldr;
    MemCpy(&ldr, peb64.Ldr, sizeof(PEB_LDR_DATA64));

    uint64_t LastEntry = peb64.Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
    LDR_DATA_TABLE_ENTRY64 head;
    head.InLoadOrderLinks.Flink = ldr.InLoadOrderModuleList.Flink;
    do
    {
        MemCpy(&head, head.InLoadOrderLinks.Flink, sizeof(LDR_DATA_TABLE_ENTRY64));
        std::unique_ptr<wchar_t[]> p(new wchar_t[head.BaseDllName.MaximumLength / 2]);
        MemCpy(p.get(), head.BaseDllName.Buffer, head.BaseDllName.MaximumLength);
        int result = _wcsicmp(lpModuleName, p.get());
        if (0 == result)
            return head.DllBase;
    }     while (head.InLoadOrderLinks.Flink != LastEntry);

    return 0;
}

template <>
FARPROC_T<CPUArchitecture::X64> Wow64Helper<CPUArchitecture::X64>::getLdrGetProcedureAddress()
{
    uint64_t modBase = m_Ntdll;

    IMAGE_DOS_HEADER hdos;
    MemCpy(&hdos, modBase, sizeof(hdos));

    IMAGE_NT_HEADERS64 hnt;
    MemCpy(&hnt, modBase + hdos.e_lfanew, sizeof(IMAGE_NT_HEADERS64));

    IMAGE_DATA_DIRECTORY& dd = hnt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (0 == dd.VirtualAddress)
        return 0;

    IMAGE_EXPORT_DIRECTORY exportDir;
    MemCpy(&exportDir, modBase + dd.VirtualAddress, sizeof(exportDir));

    std::unique_ptr<uint32_t[]> rvaTable(new uint32_t[exportDir.NumberOfFunctions]);
    MemCpy(rvaTable.get(), modBase + exportDir.AddressOfFunctions, sizeof(uint32_t) * exportDir.NumberOfFunctions);

    std::unique_ptr<uint16_t[]> ordTable(new uint16_t[exportDir.NumberOfFunctions]);
    MemCpy(ordTable.get(), modBase + exportDir.AddressOfNameOrdinals, sizeof(uint16_t) * exportDir.NumberOfFunctions);

    std::unique_ptr<uint32_t[]> nameTable(new uint32_t[exportDir.NumberOfNames]);
    MemCpy(nameTable.get(), modBase + exportDir.AddressOfNames, sizeof(uint32_t) * exportDir.NumberOfNames);

    const char target[] = "LdrGetProcedureAddress";
    for (DWORD i = 0; i < exportDir.NumberOfFunctions; ++i)
    {
        if (MemCmp(target, modBase + nameTable[i], sizeof(target)) == 0)
            return modBase + rvaTable[ordTable[i]];
    }

    return 0;
}

template <>
FARPROC_T<CPUArchitecture::X64> Wow64Helper<CPUArchitecture::X64>::GetProcAddress64(HMODULE_T<CPUArchitecture::X64> hModule, const char* funcName) const noexcept
{
    UNICODE_STRING_T<uint64_t> fName;
    fName.Buffer = (uint64_t)funcName;
    fName.Length = (WORD)strlen(funcName);
    fName.MaximumLength = fName.Length + 1;
    uint64_t funcRet = 0;
    X64Function(m_LdrGetProcedureAddress, 4, (uint64_t)hModule, (uint64_t)&fName, (uint64_t)0, (uint64_t)&funcRet);
    return funcRet;
}
#endif // !_X64_


typedef NT_STATUS (__stdcall * NtQueryVirtualMemory_t)(
    HANDLE                   ProcessHandle,
    PVOID                    BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID                    MemoryInformation,
    SIZE_T                   MemoryInformationLength,
    PSIZE_T                  ReturnLength
);

typedef NT_STATUS (__stdcall* NtQueryInformationProcess_t)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

typedef NT_STATUS (__stdcall* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

typedef NT_STATUS (__stdcall* NtAllocateVirtualMemory_t)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

typedef NT_STATUS (__stdcall* NtFreeVirtualMemory_t)(
    HANDLE  ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType
);

typedef NT_STATUS (__stdcall* NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesReaded);

typedef NT_STATUS (__stdcall* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    LPCVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten);

typedef NT_STATUS (__stdcall* NtQueryInformationThread_t)(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength,
    PULONG          ReturnLength
);

template <CPUArchitecture arch>
NT_STATUS Wow64Helper<arch>::NtQueryVirtualMemory64(HANDLE hProcess, uint64_t lpAddress, MEMORY_INFORMATION_CLASS memInfoClass,
                                                    void* lpBuffer, uint64_t dwLength, uint64_t* pReturnLength) const noexcept
{
    if (pReturnLength != nullptr)
        *pReturnLength = 0;
    return ((NtQueryVirtualMemory_t)m_NtQueryVirtualMemory)(hProcess, (PVOID)lpAddress, memInfoClass,
                                                            lpBuffer, (SIZE_T)dwLength, (PSIZE_T)pReturnLength);
}

template <CPUArchitecture arch>
NT_STATUS Wow64Helper<arch>::NtQueryInformationProcess64(HANDLE hProcess, PROCESSINFOCLASS processInfoClass,
                                                         void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept
{
    return ((NtQueryInformationProcess_t)m_NtQueryInformationProcess)(hProcess, processInfoClass, lpBuffer, dwLength, (PULONG)pReturnLength);
}

template <CPUArchitecture arch>
NT_STATUS Wow64Helper<arch>::NtQuerySystemInformation64(SYSTEM_INFORMATION_CLASS systemInfoClass,
                                                        void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept
{
    return ((NtQuerySystemInformation_t)m_NtQuerySystemInformation)(systemInfoClass, lpBuffer, dwLength, (PULONG)pReturnLength);
}

template <CPUArchitecture arch>
NT_STATUS Wow64Helper<arch>::NtQueryInformationThread64(HANDLE hProcess, THREADINFOCLASS threadInfoClass,
                                                        void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept
{
    return ((NtQueryInformationThread_t)m_NtQueryInformationThread)(hProcess, threadInfoClass, lpBuffer, dwLength, (PULONG)pReturnLength);
}

template <CPUArchitecture arch>
uint64_t Wow64Helper<arch>::VirtualAllocEx64(HANDLE hProcess, uint64_t lpAddress, uint64_t dwSize, uint32_t flAllocationType, uint32_t flProtect) const noexcept
{
    NT_STATUS status = ((NtAllocateVirtualMemory_t)m_NtAllocateVirtualMemory)(hProcess, (PVOID*)&lpAddress, 0, (PSIZE_T)&dwSize, flAllocationType, flProtect);
    return NT_SUCCESS(status) ? lpAddress : 0;
}

template <CPUArchitecture arch>
BOOL Wow64Helper<arch>::VirtualFreeEx64(HANDLE hProcess, uint64_t lpAddress, uint32_t dwSize, uint32_t dwFreeType) const noexcept
{
    NT_STATUS status = ((NtFreeVirtualMemory_t)m_NtFreeVirtualMemory)(hProcess, (PVOID*)&lpAddress, (PSIZE_T)&dwSize, dwFreeType);
    return NT_SUCCESS(status) ? TRUE : FALSE;
}

template <CPUArchitecture arch>
BOOL Wow64Helper<arch>::ReadProcessMemory64(HANDLE hProcess, uint64_t lpBaseAddress, void* lpBuffer, uint64_t nSize, uint64_t *lpNumberOfBytesRead) const noexcept
{
    if (lpNumberOfBytesRead != nullptr)
        *lpNumberOfBytesRead = 0;
    NT_STATUS ret = ((NtReadVirtualMemory_t)m_NtReadVirtualMemory)(hProcess, (PVOID)lpBaseAddress, lpBuffer, (SIZE_T)nSize, (PSIZE_T)lpNumberOfBytesRead);
    return NT_SUCCESS(ret) ? TRUE : FALSE;
}

template <CPUArchitecture arch>
BOOL Wow64Helper<arch>::WriteProcessMemory64(HANDLE hProcess, uint64_t lpBaseAddress, const void* lpBuffer, uint64_t nSize, uint64_t *lpNumberOfBytesWritten) const noexcept
{
    if (lpNumberOfBytesWritten != nullptr)
        *lpNumberOfBytesWritten = 0;
    NT_STATUS ret = ((NtWriteVirtualMemory_t)m_NtWriteVirtualMemory)(hProcess, (PVOID)lpBaseAddress, lpBuffer, (SIZE_T)nSize, (PSIZE_T)lpNumberOfBytesWritten);
    return NT_SUCCESS(ret) ? TRUE : FALSE;
}

#if !_X64_

template <>
NT_STATUS Wow64Helper<CPUArchitecture::X64>::NtQueryVirtualMemory64(HANDLE hProcess, uint64_t lpAddress, MEMORY_INFORMATION_CLASS memInfoClass,
                                                                    void* lpBuffer, uint64_t dwLength, uint64_t* pReturnLength) const noexcept
{
    return X64Function(m_NtQueryVirtualMemory, 6, (uint64_t)hProcess, lpAddress, (uint64_t)memInfoClass,
        (uint64_t)lpBuffer, (uint64_t)dwLength, (uint64_t)pReturnLength);
}

template <>
NT_STATUS Wow64Helper<CPUArchitecture::X64>::NtQueryInformationProcess64(HANDLE hProcess, PROCESSINFOCLASS processInfoClass,
                                                                         void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept
{
    return X64Function(m_NtQueryInformationProcess, 5, (uint64_t)hProcess, (uint64_t)processInfoClass, (uint64_t)lpBuffer, (uint64_t)dwLength, (uint64_t)pReturnLength);
}

template <>
NT_STATUS Wow64Helper<CPUArchitecture::X64>::NtQuerySystemInformation64(SYSTEM_INFORMATION_CLASS systemInfoClass, void* lpBuffer, 
                                                                        uint32_t dwLength, uint32_t* pReturnLength) const noexcept
{
    return X64Function(m_NtQuerySystemInformation, 4, (uint64_t)systemInfoClass, (uint64_t)lpBuffer, (uint64_t)dwLength, (uint64_t)pReturnLength);
}

template <>
NT_STATUS Wow64Helper<CPUArchitecture::X64>::NtQueryInformationThread64(HANDLE hProcess, THREADINFOCLASS threadInfoClass,
                                                                        void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept
{
    return X64Function(m_NtQueryInformationThread, 5, (uint64_t)hProcess, (uint64_t)threadInfoClass, (uint64_t)lpBuffer, (uint64_t)dwLength, (uint64_t)&pReturnLength);
}

template <>
uint64_t Wow64Helper<CPUArchitecture::X64>::VirtualAllocEx64(HANDLE hProcess, uint64_t lpAddress, uint64_t dwSize, uint32_t flAllocationType, uint32_t flProtect) const noexcept
{
    NT_STATUS status = X64Function(m_NtAllocateVirtualMemory, 6, (uint64_t)hProcess, (uint64_t)&lpAddress, (uint64_t)0, (uint64_t)&dwSize,
        (uint64_t)flAllocationType, (uint64_t)flProtect);
    return NT_SUCCESS(status) ? lpAddress : 0;
}

template <>
BOOL Wow64Helper<CPUArchitecture::X64>::VirtualFreeEx64(HANDLE hProcess, uint64_t lpAddress, uint32_t dwSize, uint32_t dwFreeType) const noexcept
{
    NT_STATUS status = X64Function(m_NtFreeVirtualMemory, 4, (uint64_t)hProcess, (uint64_t)&lpAddress, (uint64_t)&dwSize, (uint64_t)dwFreeType);
    return NT_SUCCESS(status) ? TRUE : FALSE;
}

template <>
BOOL Wow64Helper<CPUArchitecture::X64>::ReadProcessMemory64(HANDLE hProcess, uint64_t lpBaseAddress, void* lpBuffer, uint64_t nSize, uint64_t* lpNumberOfBytesRead) const noexcept
{
    NT_STATUS ret = X64Function(m_NtReadVirtualMemory, 5, (uint64_t)hProcess, lpBaseAddress, (uint64_t)lpBuffer, (uint64_t)nSize, (uint64_t)lpNumberOfBytesRead);
    return NT_SUCCESS(ret) ? TRUE : FALSE;
}

template <>
BOOL Wow64Helper<CPUArchitecture::X64>::WriteProcessMemory64(HANDLE hProcess, uint64_t lpBaseAddress, const void* lpBuffer, uint64_t nSize, uint64_t* lpNumberOfBytesWritten) const noexcept
{
    NT_STATUS ret = X64Function(m_NtWriteVirtualMemory, 5, (uint64_t)hProcess, lpBaseAddress, (uint64_t)lpBuffer, (uint64_t)nSize, (uint64_t)lpNumberOfBytesWritten);
    return NT_SUCCESS(ret) ? TRUE : FALSE;
}

template class Wow64Helper<CPUArchitecture::X86>;
#endif //_X64_

template class Wow64Helper<CPUArchitecture::X64>;

typedef BOOL (WINAPI* IsWow64Process_t)(HANDLE hProcess, PBOOL res);

CPUArchitecture GetOSArch() noexcept
{
#if _X64_
    return CPUArchitecture::X64;
#else
    auto IsWow64Process = (IsWow64Process_t)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
    if (IsWow64Process != nullptr)
    {
        BOOL IsWOW64 = FALSE;
        IsWow64Process(GetCurrentProcess(), &IsWOW64);
        return IsWOW64 ? CPUArchitecture::X64 : CPUArchitecture::X86;
    }

    return CPUArchitecture::X86;
#endif // _X64_
}

CPUArchitecture GetProcessArch(HANDLE hProcess) noexcept
{
    auto IsWow64Process = (IsWow64Process_t)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
    if (IsWow64Process != nullptr)
    {
        BOOL IsWOW64 = FALSE;
        IsWow64Process(hProcess, &IsWOW64);
        return IsWOW64 ? CPUArchitecture::X86 : GetOSArch();
    }

    return GetOSArch();
}

