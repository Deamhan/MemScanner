#pragma once

#include <cstdint>
#include <windows.h>
#include "system_defs.h"

#pragma pack(push, 1)

enum class CPUArchitecture
{
#if !_X64_
    X86,
#endif // !_X64_
    X64
};

template <CPUArchitecture arch>
struct HelperTraits
{
    typedef HMODULE HMODULE_T;
    typedef FARPROC FARPROC_T;
#if _X64_
    typedef uint64_t PTR_T;
#else
    typedef uint32_t PTR_T;
#endif
};

#if !_X64_
template <>
struct HelperTraits<CPUArchitecture::X64>
{
    typedef uint64_t HMODULE_T;
    typedef uint64_t FARPROC_T;
    typedef uint64_t PTR_T;
};
#endif // _X64_

template <CPUArchitecture arch>
using HMODULE_T = typename HelperTraits<arch>::HMODULE_T;

template <CPUArchitecture arch>
using FARPROC_T = typename HelperTraits<arch>::FARPROC_T;

template <CPUArchitecture arch>
using PTR_T = typename HelperTraits<arch>::PTR_T;

template <CPUArchitecture arch>
class Wow64Helper
{
public:
    bool IsOK() const noexcept { return m_isOk; }
    HMODULE_T<arch> GetModuleHandle64(const wchar_t* lpModuleName) const noexcept;
    FARPROC_T<arch> GetProcAddress64(HMODULE_T<arch> hModule, const char* funcName) const noexcept;
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
    HMODULE_T<arch> m_Ntdll;
    FARPROC_T<arch> m_LdrGetProcedureAddress;
    FARPROC_T<arch> m_NtQueryVirtualMemory;
    FARPROC_T<arch> m_NtAllocateVirtualMemory;
    FARPROC_T<arch> m_NtFreeVirtualMemory;
    FARPROC_T<arch> m_NtReadVirtualMemory;
    FARPROC_T<arch> m_NtWriteVirtualMemory;
    FARPROC_T<arch> m_NtGetContextThread;
    FARPROC_T<arch> m_NtSetContextThread;
    FARPROC_T<arch> m_NtQuerySystemInformation;
    FARPROC_T<arch> m_NtQueryInformationProcess;
    FARPROC_T<arch> m_NtQueryInformationThread;
    bool m_isOk;

    FARPROC_T<arch> getLdrGetProcedureAddress();

    Wow64Helper();

    template <CPUArchitecture arch>
    friend const Wow64Helper<arch>& GetWow64Helper();
};

template <CPUArchitecture arch>
const Wow64Helper<arch>& GetWow64Helper();

CPUArchitecture GetOSArch() noexcept;
CPUArchitecture GetProcessArch(HANDLE hProcess) noexcept;

