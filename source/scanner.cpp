#include "scanner.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "ntdll64.h"

#undef max

using namespace SystemDefinitions;

static void CloseHandleByPtr(HANDLE* handle)
{
	CloseHandle(*handle);
}

typedef unsigned long long ull;

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
    switch (prot & 0xFF)
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
        return L"Invalid attributes";
    }
}

const uint32_t PAGE_SIZE = 4096;

template <CPUArchitecture arch>
static std::vector<MEMORY_BASIC_INFORMATION_T<PTR_T<arch>>> GetMemoryMap(HANDLE hProcess, const Wow64Helper<arch>& api)
{
    std::vector<MEMORY_BASIC_INFORMATION_T<PTR_T<arch>>> result;
    PTR_T<arch> address = 0;
    MEMORY_BASIC_INFORMATION_T<PTR_T<arch>> mbi;
    while (NT_SUCCESS(api.NtQueryVirtualMemory64(hProcess, address, MEMORY_INFORMATION_CLASS::MemoryBasicInformation, &mbi, sizeof(mbi), nullptr)))
    {
        if ((mbi.State & MEM_COMMIT) != 0 && mbi.Type != MemType::Image)
            result.push_back(mbi);
        auto prevAddr = address;
        address += std::max<PTR_T<arch>>(mbi.RegionSize, PAGE_SIZE);
        if (prevAddr > address)
            break;
    }

    return result;
}

static const char dumpSignature[] = "MEMDUMP";

/*
* Process dump file structure:
* | signature | os bitness | suspicious thread count | suspicious threads ep[] | memory regions count | MEMORY_BASIC_INFORMATION_T [] | raw mwmory regions[] |
*/

template <CPUArchitecture arch>
static bool DumpMemory(HANDLE hProcess, uint32_t pid, const wchar_t* process, const wchar_t* path, const std::vector<PTR_T<arch>>& processIssues, const Wow64Helper<arch>& api)
{
    FILE* dump = nullptr;
    _wfopen_s(&dump, path, L"wb");
    if (dump != nullptr)
    {
        constexpr size_t sigLen = sizeof(dumpSignature) / sizeof(dumpSignature[0]);
        if (fwrite(dumpSignature, sizeof(dumpSignature[0]), sigLen, dump) != sigLen)
        {
            wprintf(L"!>> Unable to write data to file %s <<!\n", path);
            return false;
        }

        uint8_t bitness = (arch == CPUArchitecture::X64 ? 64 : 32);
        if (fwrite(&bitness, sizeof(bitness), 1, dump) != 1)
        {
            wprintf(L"!>> Unable to write data to file %s <<!\n", path);
            return false;
        }

        std::unique_ptr<FILE, int(*)(FILE*)> dumpGuard(dump, fclose);
        const uint32_t issuesCount = (uint32_t)processIssues.size();
        if (fwrite(&issuesCount, sizeof(issuesCount), 1, dump) != 1)
        {
            wprintf(L"!>> Unable to write data to file %s <<!\n", path);
            return false;
        }

        if (fwrite(processIssues.data(), sizeof(processIssues[0]), issuesCount, dump) != issuesCount)
        {
            wprintf(L"!>> Unable to write data to file %s <<!\n", path);
            return false;
        }

        auto mm = GetMemoryMap<arch>(hProcess, api);
        const uint32_t mmSize = (uint32_t)mm.size();
        if (fwrite(&mmSize, sizeof(mmSize), 1, dump) != 1)
        {
            wprintf(L"!>> Unable to write data to file %s <<!\n", path);
            return false;
        }

        if (fwrite(mm.data(), sizeof(mm[0]), mmSize, dump) != mmSize)
        {
            wprintf(L"!>> Unable to write data to file %s <<!\n", path);
            return false;
        }

        std::vector<uint8_t> readBuffer(1024 * 1024);
        for (const auto& mbi : mm)
        {
            uint64_t size = mbi.RegionSize, processed = 0;
            while (size != 0)
            {
                size_t blockSize = (size_t)std::min<uint64_t>(readBuffer.size(), size);
                uint64_t result;
                const uint64_t addr = mbi.BaseAddress + processed;
                memset(readBuffer.data(), 0, blockSize);
                if (!api.ReadProcessMemory64(hProcess, addr, readBuffer.data(), blockSize, &result))
                    wprintf(L"!>> Unable to read process memory [%s, PID = %u] [0x%016llx : 0x%016llx) <<!\n", process, (unsigned)pid, (ull)addr, (ull)(addr + blockSize));

                if (fwrite(readBuffer.data(), sizeof(uint8_t), blockSize, dump) != blockSize)
                {
                    wprintf(L"!>> Unable to write data to file %s <<!\n", path);
                    return false;
                }

                size -= blockSize;
                processed += blockSize;
            }
        }

        return true;
    }
    else
        wprintf(L"!>> Unable to open file %s for writing <<!\n", path);

    return false;
}

template <CPUArchitecture arch>
static int ScanMemoryImpl(const wchar_t * dumpDir)
{
    wprintf(L">>> OS Architecture: %s <<<\n", arch == CPUArchitecture::X64 ? L"X64" : L"X86");
    wprintf(L">>> Scanner Architecture: %s <<<\n", sizeof(void*) == 8 ? L"X64" : L"X86");

    int issues = 0;

    if (!EnableDebugPrivilege())
        wprintf(L"!>> Unable to enable SeDebugPrivilege, functionality is limited <<!\n");

    auto& api = GetWow64Helper<arch>();

    std::vector<uint8_t> buffer(64 * 1024);
    uint32_t resLen = 0;
    while (IsBufferTooSmall(api.NtQuerySystemInformation64(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, buffer.data(), (uint32_t)buffer.size(), &resLen)))
        buffer.resize(resLen);

    typedef SYSTEM_PROCESS_INFORMATION_T<PTR_T<arch>> SPI, * PSPI;
    auto procInfo = (const PSPI)buffer.data();
    for (bool stop = false; !stop;
        stop = (procInfo->NextEntryOffset == 0), procInfo = (PSPI)((uint8_t*)procInfo + procInfo->NextEntryOffset))
    {
        std::wstring name((const wchar_t*)procInfo->ImageName.Buffer, procInfo->ImageName.Length / sizeof(wchar_t));
        wprintf(L"Process %s [PID = %u]", name.c_str(), (unsigned)(uintptr_t)procInfo->ProcessId);

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)(uintptr_t)procInfo->ProcessId);
        if (hProcess == nullptr)
        {
            wprintf(L": unanle to open\n");
            continue;
        }
        
        wprintf(L"\n");
        std::vector<PTR_T<arch>> processIssues;
        std::unique_ptr<HANDLE, void(*)(HANDLE*)> processGuard(&hProcess, CloseHandleByPtr);
        for (uint32_t i = 0; i < procInfo->NumberOfThreads; ++i)
        {
            PTR_T<arch> startAddress = 0;
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, (DWORD)(uintptr_t)procInfo->Threads[i].ClientId.UniqueThread);
            if (hThread == nullptr)
                continue;

            std::unique_ptr<HANDLE, void(*)(HANDLE*)> threadGuard(&hThread, CloseHandleByPtr);
            if (NT_SUCCESS(api.NtQueryInformationThread64(hThread, THREADINFOCLASS::ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), nullptr)))
            {
                MEMORY_BASIC_INFORMATION_T<PTR_T<arch>> mbi = {};
                if (NT_SUCCESS(api.NtQueryVirtualMemory64(hProcess, startAddress, MEMORY_INFORMATION_CLASS::MemoryBasicInformation, &mbi, sizeof(mbi), nullptr))
                    && (mbi.State & MEM_COMMIT) != 0 && mbi.Type != MemType::Image)
                {
                    ++issues;
                    processIssues.push_back(startAddress);
                    wprintf(L"\t Suspicious thread [TID = %u]: Start address == 0x%016llx (%s)\n", (unsigned)(uintptr_t)procInfo->Threads[i].ClientId.UniqueThread, (ull)startAddress, ProtToStr(mbi.Protect));
                }
            }
        }

        if (!processIssues.empty() && dumpDir != nullptr)
        {
            std::wstring path(dumpDir);
            path += L'\\';
            path += std::to_wstring((unsigned)(uintptr_t)procInfo->ProcessId);
            path += L".dump";
            
            DumpMemory<arch>(hProcess, (uint32_t)(uintptr_t)procInfo->ProcessId, name.c_str(), path.c_str(), processIssues, api);
        }
    }

    return issues;
}

#if _X64_
int ScanMemory(const wchar_t* dumpDir)
{
    return ScanMemoryImpl<CPUArchitecture::X64>(dumpDir);
}
#else
int ScanMemory(const wchar_t* dumpDir)
{
    return (GetOSArch() == CPUArchitecture::X64 ? ScanMemoryImpl<CPUArchitecture::X64>(dumpDir) : ScanMemoryImpl<CPUArchitecture::X86>(dumpDir));
}
#endif


