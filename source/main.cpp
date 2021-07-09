#include "ntdll64.h"

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

using namespace SystemDefinitions;

int main(int argc, const char ** argv)
{
    HANDLE hToken;
    LUID DebugValue;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return 1;

    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &DebugValue))
        return 2;

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = DebugValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
        return 3;

    CloseHandle(hToken);

    auto& api = GetWow64Helper();

    std::vector<uint8_t> buffer(64 * 1024);
    uint32_t resLen = 0;
    while (IsBufferTooSmall(api.NtQuerySystemInformation64(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, buffer.data(), buffer.size(), &resLen)))
        buffer.resize(resLen);

    typedef SYSTEM_PROCESS_INFORMATION_T<uint64_t> SPI64, *PSPI64;
    auto procInfo = (const PSPI64)buffer.data();
    for (bool stop = false; !stop;
         stop = (procInfo->NextEntryOffset == 0), procInfo = (PSPI64)((uint8_t*)procInfo + procInfo->NextEntryOffset))
    {
        std::wstring name((const wchar_t*)procInfo->ImageName.Buffer, procInfo->ImageName.Length / sizeof(wchar_t));
        wprintf(L"Process %s [PID = %u]\n", name.c_str(), (unsigned)procInfo->ProcessId);

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)procInfo->ProcessId);
        if (hProcess == nullptr)
            continue;

        for (uint32_t i = 0; i < procInfo->NumberOfThreads; ++i)
        {
            unsigned long long startAddress = 0;
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, (DWORD)procInfo->Threads[i].ClientId.UniqueThread);
            if (hThread == nullptr)
                continue;

            if (NT_SUCCESS(api.NtQueryInformationThread64(hThread, THREADINFOCLASS::ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), nullptr)))
            {
                MEMORY_BASIC_INFORMATION_T<uint64_t> mbi = {};
                if (NT_SUCCESS(api.NtQueryVirtualMemory64(hProcess, startAddress, MEMORY_INFORMATION_CLASS::MemoryBasicInformation, &mbi, sizeof(mbi), nullptr))
                    && (mbi.State & MEM_COMMIT) != 0 && mbi.Type != MemType::Image)
                {
                    bool isExec = false;
                    std::wstring attr;
                    switch (mbi.Protect)
                    {
                    case PAGE_EXECUTE:
                        isExec = true;
                        attr = L"X";
                        break;
                    case PAGE_EXECUTE_READ:
                        isExec = true;
                        attr = L"RX";
                        break;
                    case PAGE_EXECUTE_READWRITE:
                        isExec = true;
                        attr = L"RWX";
                        break;
                    case PAGE_EXECUTE_WRITECOPY:
                        isExec = true;
                        attr = L"RWX(C)";
                        break;
                    }
                    wprintf(L"\t Suspicious thread [TID = %u]: Start address == 0x%016llx (%s)\n", (unsigned)procInfo->Threads[i].ClientId.UniqueThread, startAddress, attr.c_str());
                }
            }

            CloseHandle(hThread);
        }

        CloseHandle(hProcess);
    }

    return 0;
}
