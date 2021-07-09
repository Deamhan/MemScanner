#include "scanner.h"

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "ntdll64.h"

using namespace SystemDefinitions;

static void CloseHandleByPtr(HANDLE* handle)
{
	CloseHandle(*handle);
}

static bool EnableDebugPrivilege()
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

static const wchar_t* ProtToStr(uint32_t prot)
{
    switch (prot)
    {
    case PAGE_EXECUTE:
        return L"X";
    case PAGE_EXECUTE_READ:
        return L"RX";
    case PAGE_EXECUTE_READWRITE:
        return L"RWX";
    case PAGE_EXECUTE_WRITECOPY:
        return L"RWX(C)";
    default:
        return L"Invalid attribtes";
    }
}

int ScanMemory()
{
    int issues = 0;

    if (!EnableDebugPrivilege())
        wprintf(L"!>> Unable to enable SeDebugPrivilege, functionality is limited <<!\n");

    auto& api = GetWow64Helper();

    std::vector<uint8_t> buffer(64 * 1024);
    uint32_t resLen = 0;
    while (IsBufferTooSmall(api.NtQuerySystemInformation64(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, buffer.data(), buffer.size(), &resLen)))
        buffer.resize(resLen);

    typedef SYSTEM_PROCESS_INFORMATION_T<uint64_t> SPI64, * PSPI64;
    auto procInfo = (const PSPI64)buffer.data();
    for (bool stop = false; !stop;
        stop = (procInfo->NextEntryOffset == 0), procInfo = (PSPI64)((uint8_t*)procInfo + procInfo->NextEntryOffset))
    {
        std::wstring name((const wchar_t*)procInfo->ImageName.Buffer, procInfo->ImageName.Length / sizeof(wchar_t));
        wprintf(L"Process %s [PID = %u]\n", name.c_str(), (unsigned)procInfo->ProcessId);

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)procInfo->ProcessId);
        if (hProcess == nullptr)
            continue;

        std::unique_ptr<HANDLE, void(*)(HANDLE*)> processGuard(&hProcess, CloseHandleByPtr);
        for (uint32_t i = 0; i < procInfo->NumberOfThreads; ++i)
        {
            unsigned long long startAddress = 0;
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, (DWORD)procInfo->Threads[i].ClientId.UniqueThread);
            if (hThread == nullptr)
                continue;

            std::unique_ptr<HANDLE, void(*)(HANDLE*)> threadGuard(&hThread, CloseHandleByPtr);
            if (NT_SUCCESS(api.NtQueryInformationThread64(hThread, THREADINFOCLASS::ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), nullptr)))
            {
                MEMORY_BASIC_INFORMATION_T<uint64_t> mbi = {};
                if (NT_SUCCESS(api.NtQueryVirtualMemory64(hProcess, startAddress, MEMORY_INFORMATION_CLASS::MemoryBasicInformation, &mbi, sizeof(mbi), nullptr))
                    && (mbi.State & MEM_COMMIT) != 0 && mbi.Type != MemType::Image)
                {
                    ++issues;
                    wprintf(L"\t Suspicious thread [TID = %u]: Start address == 0x%016llx (%s)\n", (unsigned)procInfo->Threads[i].ClientId.UniqueThread, startAddress, ProtToStr(mbi.Protect));
                }
            }
        }
    }

    return issues;
}