#pragma once

#include <cstdint>
#include <windows.h>
#include "system_defs.h"

#pragma pack(push, 1)

class Wow64Helper
{
private:
    uint64_t m_Ntdll64;
    uint64_t m_LdrGetProcedureAddress;
    uint64_t m_NtQueryVirtualMemory;
    uint64_t m_NtAllocateVirtualMemory;
    uint64_t m_NtFreeVirtualMemory;
    uint64_t m_NtReadVirtualMemory;
    uint64_t m_NtWriteVirtualMemory;
    uint64_t m_NtGetContextThread;
    uint64_t m_NtSetContextThread;
    uint64_t m_NtQuerySystemInformation;
    uint64_t m_NtQueryInformationProcess;
    uint64_t m_NtQueryInformationThread;
    bool     m_isOk;

    uint64_t getLdrGetProcedureAddress();

    Wow64Helper();

    friend const Wow64Helper& GetWow64Helper();
public:
    bool IsOK() const noexcept { return m_isOk; }

    uint64_t GetModuleHandle64(const wchar_t* lpModuleName) const noexcept;
    uint64_t GetProcAddress64(uint64_t hModule, const char* funcName) const noexcept;
    SystemDefinitions::NT_STATUS NtQueryVirtualMemory64(HANDLE hProcess, uint64_t lpAddress, SystemDefinitions::MEMORY_INFORMATION_CLASS memInfoClass,
                                                        void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept;
    SystemDefinitions::NT_STATUS NtQueryInformationProcess64(HANDLE hProcess, SystemDefinitions::PROCESSINFOCLASS procInfoClass,
                                                             void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept;
    SystemDefinitions::NT_STATUS NtQueryInformationThread64(HANDLE hProcess, SystemDefinitions::THREADINFOCLASS threadInfoClass,
                                                            void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept;
    SystemDefinitions::NT_STATUS NtQuerySystemInformation64(SystemDefinitions::SYSTEM_INFORMATION_CLASS SystemInformation,
                                                            void* lpBuffer, uint32_t dwLength, uint32_t* pReturnLength) const noexcept;
    uint64_t VirtualAllocEx64(HANDLE hProcess, uint64_t lpAddress, uint32_t dwSize, uint32_t flAllocationType, uint32_t flProtect) const noexcept;
    BOOL    VirtualFreeEx64(HANDLE hProcess, uint64_t lpAddress, uint32_t dwSize, uint32_t dwFreeType) const noexcept;
    BOOL    ReadProcessMemory64(HANDLE hProcess, uint64_t lpBaseAddress, void* lpBuffer, uint32_t nSize, uint32_t* lpNumberOfBytesRead) const noexcept;
    BOOL    WriteProcessMemory64(HANDLE hProcess, uint64_t lpBaseAddress, const void* lpBuffer, uint32_t nSize, uint32_t* lpNumberOfBytesWritten) const noexcept;
};

const Wow64Helper& GetWow64Helper();

