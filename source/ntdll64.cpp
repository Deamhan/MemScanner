#include "ntdll64.h"

#include <memory>

extern "C" uint32_t X64Function(uint64_t Func, uint32_t Argc, uint64_t Arg0, uint64_t Arg1, uint64_t Arg2, uint64_t Arg3, ...);
extern "C" void MemCpy(void* pDest, uint64_t pSource, uint32_t size);
extern "C" int  MemCmp(const void* pDest, uint64_t pSource, uint32_t size);
extern "C" void GetTEB64(uint64_t* pTeb64);

#define SURE(f) if ((f) == 0) return

using namespace SystemDefinitions;

const Wow64Helper& GetWow64Helper()
{ 
    static Wow64Helper api;
    return api;
}

Wow64Helper::Wow64Helper() : m_isOk(false)
{
    SURE(m_Ntdll64 = GetModuleHandle64(L"ntdll.dll"));
    SURE(m_LdrGetProcedureAddress = getLdrGetProcedureAddress());
    SURE(m_NtQueryVirtualMemory = GetProcAddress64(m_Ntdll64, "NtQueryVirtualMemory"));
    SURE(m_NtAllocateVirtualMemory = GetProcAddress64(m_Ntdll64, "NtAllocateVirtualMemory"));
    SURE(m_NtFreeVirtualMemory = GetProcAddress64(m_Ntdll64, "NtFreeVirtualMemory"));
    SURE(m_NtReadVirtualMemory = GetProcAddress64(m_Ntdll64, "NtReadVirtualMemory"));
    SURE(m_NtWriteVirtualMemory = GetProcAddress64(m_Ntdll64, "NtWriteVirtualMemory"));
    SURE(m_NtGetContextThread = GetProcAddress64(m_Ntdll64,   "NtGetContextThread"));
    SURE(m_NtSetContextThread = GetProcAddress64(m_Ntdll64,   "NtSetContextThread"));
    SURE(m_NtQueryInformationProcess = GetProcAddress64(m_Ntdll64, "NtQueryInformationProcess"));
    SURE(m_NtQueryInformationThread  = GetProcAddress64(m_Ntdll64, "NtQueryInformationThread"));
    SURE(m_NtQuerySystemInformation  = GetProcAddress64(m_Ntdll64, "NtQuerySystemInformation"));

    m_isOk = true;
}

uint64_t Wow64Helper::GetModuleHandle64(const wchar_t* lpModuleName) const noexcept
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
    }
    while (head.InLoadOrderLinks.Flink != LastEntry);

    return 0;
}

uint64_t Wow64Helper::getLdrGetProcedureAddress() 
{
    uint64_t modBase = m_Ntdll64;

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

uint64_t Wow64Helper::GetProcAddress64(uint64_t hModule, const char* funcName) const noexcept
{
    UNICODE_STRING_T<uint64_t> fName;
    fName.Buffer = (uint64_t)funcName;
    fName.Length = (WORD)strlen(funcName);
    fName.MaximumLength = fName.Length + 1;
    uint64_t funcRet = 0;
    X64Function(m_LdrGetProcedureAddress, 4, (uint64_t)hModule, (uint64_t)&fName, (uint64_t)0, (uint64_t)&funcRet);
    return funcRet;
}

DWORD Wow64Helper::NtQueryVirtualMemory64(HANDLE hProcess, uint64_t lpAddress, MEMORY_INFORMATION_CLASS memInfoClass,
                                       void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept
{
    uint64_t retLength = 0;
    DWORD   status;
    status = X64Function(m_NtQueryVirtualMemory, 6, (uint64_t)hProcess, lpAddress, (uint64_t)memInfoClass,
                           (uint64_t)lpBuffer, (uint64_t)dwLength, (uint64_t)&retLength);
    if (pReturnLength)
        *pReturnLength = (uint32_t)retLength;
    return status;
}

DWORD Wow64Helper::NtQueryInformationProcess64(HANDLE hProcess, PROCESSINFOCLASS processInfoClass,
                                            void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept
{
    return X64Function(m_NtQueryInformationProcess, 5, (uint64_t)hProcess, (uint64_t)processInfoClass, (uint64_t)lpBuffer, (uint64_t)dwLength, (uint64_t) pReturnLength);
}

DWORD Wow64Helper::NtQuerySystemInformation64(SYSTEM_INFORMATION_CLASS systemInfoClass,
                                           void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept
{
    return X64Function(m_NtQuerySystemInformation, 4, (uint64_t)systemInfoClass, (uint64_t)lpBuffer, (uint64_t)dwLength, (uint64_t) pReturnLength);
}

DWORD Wow64Helper::NtQueryInformationThread64(HANDLE hProcess, THREADINFOCLASS threadInfoClass,
                                           void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept
{
    return X64Function(m_NtQueryInformationThread, 5, (uint64_t)hProcess, (uint64_t)threadInfoClass, (uint64_t)lpBuffer, (uint64_t)dwLength, (uint64_t)&pReturnLength);
}

uint64_t Wow64Helper::VirtualAllocEx64(HANDLE hProcess, uint64_t lpAddress, uint32_t dwSize, uint32_t flAllocationType, uint32_t flProtect) const noexcept
{
    uint64_t tmpAddr = lpAddress;
    uint64_t tmpSize = dwSize;
    DWORD   status  = X64Function(m_NtAllocateVirtualMemory, 6, (uint64_t)hProcess, (uint64_t)&tmpAddr, (uint64_t)0, (uint64_t)&tmpSize,
                                    (uint64_t)flAllocationType, (uint64_t)flProtect);
    return IsSuccess(status) ? tmpAddr : 0;
}

BOOL Wow64Helper::VirtualFreeEx64(HANDLE hProcess, uint64_t lpAddress, uint32_t dwSize, uint32_t dwFreeType) const noexcept
{
    uint64_t tmpAddr = lpAddress;
    uint64_t tmpSize = dwSize;
    DWORD   ret = X64Function(m_NtFreeVirtualMemory, 4, (uint64_t)hProcess, (uint64_t)&tmpAddr, (uint64_t)&tmpSize, (uint64_t)dwFreeType);
    return IsSuccess(ret) ? TRUE : FALSE;
}

BOOL Wow64Helper::ReadProcessMemory64(HANDLE hProcess, uint64_t lpBaseAddress, void* lpBuffer, uint32_t nSize, uint32_t *lpNumberOfBytesRead) const noexcept
{
    uint64_t readCount = 0;
    DWORD ret = X64Function(m_NtReadVirtualMemory, 5, (uint64_t)hProcess, lpBaseAddress, (uint64_t)lpBuffer, (uint64_t)nSize, (uint64_t)&readCount);
    if (lpNumberOfBytesRead != nullptr)
        *lpNumberOfBytesRead = (SIZE_T)readCount;
    return IsSuccess(ret) ? TRUE : FALSE;
}

BOOL Wow64Helper::WriteProcessMemory64(HANDLE hProcess, uint64_t lpBaseAddress, const void* lpBuffer, uint32_t nSize, uint32_t *lpNumberOfBytesWritten) const noexcept
{
    uint64_t writeCount = 0;
    DWORD ret = X64Function(m_NtWriteVirtualMemory, 5, (uint64_t)hProcess, lpBaseAddress, (uint64_t)lpBuffer,
                              (uint64_t)nSize, (uint64_t)&writeCount);
    if (lpNumberOfBytesWritten != nullptr)
        *lpNumberOfBytesWritten = (SIZE_T)writeCount;
    return IsSuccess(ret) ? TRUE : FALSE;
}
