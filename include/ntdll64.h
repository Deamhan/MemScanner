#pragma once

#include <cstdint>
#include <windows.h>
#include "system_defs.h"

#pragma pack(push, 1)

#if _X64_
typedef HMODULE HMODULE_T;
typedef FARPROC FARPROC_T;
#else
typedef uint64_t HMODULE_T;
typedef uint64_t FARPROC_T;
#endif // _X64_

class Wow64Helper
{
public:
    bool IsOK() const noexcept { return m_isOk; }
#if !_X64_
    uint64_t GetModuleHandle64(const wchar_t* lpModuleName) const noexcept;
    uint64_t GetProcAddress64(uint64_t hModule, const char* funcName) const noexcept;
#endif // !_X64_
    SystemDefinitions::NT_STATUS NtQueryVirtualMemory64(HANDLE hProcess, uint64_t lpAddress, SystemDefinitions::MEMORY_INFORMATION_CLASS memInfoClass,
        void* lpBuffer, uint64_t dwLength, uint64_t* pReturnLength) const noexcept;
    SystemDefinitions::NT_STATUS NtQueryInformationProcess64(HANDLE hProcess, SystemDefinitions::PROCESSINFOCLASS procInfoClass,
        void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept;
    SystemDefinitions::NT_STATUS NtQueryInformationThread64(HANDLE hProcess, SystemDefinitions::THREADINFOCLASS threadInfoClass,
        void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept;
    SystemDefinitions::NT_STATUS NtQuerySystemInformation64(SystemDefinitions::SYSTEM_INFORMATION_CLASS SystemInformation,
        void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept;
    uint64_t VirtualAllocEx64(HANDLE hProcess, uint64_t lpAddress, uint64_t dwSize, uint32_t flAllocationType, uint32_t flProtect) const noexcept;
    BOOL    VirtualFreeEx64(HANDLE hProcess, uint64_t lpAddress, uint32_t dwSize, uint32_t dwFreeType) const noexcept;
    BOOL    ReadProcessMemory64(HANDLE hProcess, uint64_t lpBaseAddress, void* lpBuffer, uint64_t nSize, uint64_t* lpNumberOfBytesRead) const noexcept;
    BOOL    WriteProcessMemory64(HANDLE hProcess, uint64_t lpBaseAddress, const void* lpBuffer, uint64_t nSize, uint64_t* lpNumberOfBytesWritten) const noexcept;

private:
    HMODULE_T m_Ntdll64;
#if !_X64_
    FARPROC_T m_LdrGetProcedureAddress;
#endif // !_X64_
    FARPROC_T m_NtQueryVirtualMemory;
    FARPROC_T m_NtAllocateVirtualMemory;
    FARPROC_T m_NtFreeVirtualMemory;
    FARPROC_T m_NtReadVirtualMemory;
    FARPROC_T m_NtWriteVirtualMemory;
    FARPROC_T m_NtGetContextThread;
    FARPROC_T m_NtSetContextThread;
    FARPROC_T m_NtQuerySystemInformation;
    FARPROC_T m_NtQueryInformationProcess;
    FARPROC_T m_NtQueryInformationThread;
    bool     m_isOk;

#if !_X64_
    uint64_t getLdrGetProcedureAddress();
#endif // !_X64_

    Wow64Helper();

    friend const Wow64Helper& GetWow64Helper();
};

const Wow64Helper& GetWow64Helper();

