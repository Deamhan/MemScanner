#include "scanner.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#include "dump.hpp"
#include "ntdll64.hpp"

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

const uint32_t PAGE_SIZE = 4096;

template <CPUArchitecture arch>
using MemoryMap_t = std::vector<MEMORY_BASIC_INFORMATION_T<PTR_T<arch>>>;

template <CPUArchitecture arch>
static MemoryMap_t<arch> GetMemoryMap(HANDLE hProcess, const Wow64Helper<arch>& api)
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

template <class T>
static bool writeValue(const T& value, FILE* f) noexcept
{
    return fwrite(&value, sizeof(value), 1, f) == 1;
}

template <class T>
static bool writeValue(const std::vector<T>& value, FILE* f) noexcept
{
    return fwrite(value.data(), sizeof(T), value.size(), f) == value.size();
}

template <class T>
static bool writeValue(const std::vector<T>& value, size_t count, FILE* f) noexcept
{
    return fwrite(value.data(), sizeof(T), count, f) == count;
}

template <class T, int N>
static bool writeValue(const T (&value)[N], FILE* f) noexcept
{
    return fwrite(value, sizeof(T), N, f) == N;
}

/*
* Process dump file structure:
* | signature | os bitness | process bitness | suspicious thread count | suspicious threads ep[] | memory regions count | MEMORY_BASIC_INFORMATION_T [] | raw memory regions[] |
*/

template <CPUArchitecture arch>
static bool DumpMemory(HANDLE hProcess, uint32_t pid, const wchar_t* process, const wchar_t* path, const std::vector<PTR_T<arch>>& processIssues,
                       const MemoryMap_t<arch>& mm, const Wow64Helper<arch>& api)
{
    FILE* dump = nullptr;
    _wfopen_s(&dump, path, L"wb");
    if (dump != nullptr)
    {
        std::unique_ptr<FILE, int(*)(FILE*)> dumpGuard(dump, fclose);
        try
        {
            if (!writeValue(DumpSignature, dump))
                throw std::system_error(errno, std::iostream_category(), "");

            uint8_t osBitness = (arch == CPUArchitecture::X64 ? 64 : 32);
            if (!writeValue(osBitness, dump))
                throw std::system_error(errno, std::iostream_category(), "");

            uint8_t procBitness = (GetProcessArch(hProcess) == CPUArchitecture::X64 ? 64 : 32);
            if (!writeValue(procBitness, dump))
                throw std::system_error(errno, std::iostream_category(), "");

            const uint32_t issuesCount = (uint32_t)processIssues.size();
            if (!writeValue(issuesCount, dump))
                throw std::system_error(errno, std::iostream_category(), "");

            if (issuesCount != 0)
            {
                if (!writeValue(processIssues, dump))
                    throw std::system_error(errno, std::iostream_category(), "");
            }

            const uint32_t mmSize = (uint32_t)mm.size();
            if (!writeValue(mmSize, dump))
                throw std::system_error(errno, std::iostream_category(), "");

            if (!writeValue(mm, dump))
                throw std::system_error(errno, std::iostream_category(), "");

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

                    if (!writeValue(readBuffer, blockSize, dump))
                        throw std::system_error(errno, std::iostream_category(), "");

                    size -= blockSize;
                    processed += blockSize;
                }
            }

            return true;
        }
        catch (const std::system_error&)
        {
            wprintf(L"!>> Unable to write data to file %s <<!\n", path);
            return false;
        }
    }
    else
        wprintf(L"!>> Unable to open file %s for writing <<!\n", path);

    return false;
}

template <CPUArchitecture arch, typename SPI = SYSTEM_PROCESS_INFORMATION_T<PTR_T<arch>>>
static void ScanProcessMemory(SPI* procInfo, const Wow64Helper<arch>& api, int& issues, uint32_t sensitivity, const wchar_t* dumpDir)
{
    DWORD pid = (DWORD)(uint64_t)procInfo->ProcessId;
    std::wstring name((const wchar_t*)procInfo->ImageName.Buffer, procInfo->ImageName.Length / sizeof(wchar_t));

    wprintf(L"Process %s [PID = %u]", name.c_str(), (unsigned)pid);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == nullptr)
    {
        wprintf(L": unable to open\n");
        return;
    }
    wprintf(L"\n");

    bool hasExecPrivateMemory = false;
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
                processIssues.push_back(startAddress);
                wprintf(L"\t Suspicious thread [TID = %u]: Start address == 0x%016llx (%s)\n", (unsigned)(uintptr_t)procInfo->Threads[i].ClientId.UniqueThread, (ull)startAddress, ProtToStr(mbi.Protect).c_str());
                hasExecPrivateMemory = true;
                ++issues;
            }
        }
    }

    auto mm = GetMemoryMap(hProcess, api);
    if (sensitivity > 0)
    {
        for (const auto& region : mm)
        {
            uint32_t allocProtMask = 0, protMask = 0;
            switch (sensitivity)
            {
            case 1:
                protMask = (WFlag | XFlag);
                break;
            case 2:
                protMask = XFlag;
                break;
            case 3:
                protMask = XFlag;
                allocProtMask = (WFlag | XFlag);
                break;
            default:
            case 4:
                allocProtMask = protMask = XFlag;
                break;
            }

            bool isSuspRegion = false;
            bool allocProtRes = (allocProtMask != 0 ? (protToFlags(region.AllocationProtect) & allocProtMask) == allocProtMask : false);
            bool protRes = (protMask != 0 ? (protToFlags(region.Protect) & protMask) == protMask : false);
            isSuspRegion = region.Type != MemType::Image && (region.State & MEM_COMMIT) != 0 && (protRes || allocProtRes);

            if (isSuspRegion)
            {
                hasExecPrivateMemory = true;
                ++issues;
                wprintf(L"\t Suspicious memory region:\n");
                printMBI(&region, L"\t");
            }
        }
    }

    if (hasExecPrivateMemory && dumpDir != nullptr)
    {
        std::wstring path(dumpDir);
        path += L'\\';
        path += std::to_wstring((unsigned)(uintptr_t)procInfo->ProcessId);
        path += L".dump";

        DumpMemory<arch>(hProcess, (uint32_t)(uintptr_t)procInfo->ProcessId, name.c_str(), path.c_str(), processIssues, mm, api);
    }
}

template <CPUArchitecture arch>
static int ScanMemoryImpl(uint32_t sensitivity, uint32_t pid, const wchar_t* dumpDir)
{
    int issues = 0;

    wprintf(L">>> OS Architecture: %s <<<\n", arch == CPUArchitecture::X64 ? L"X64" : L"X86");
    wprintf(L">>> Scanner Architecture: %s <<<\n", sizeof(void*) == 8 ? L"X64" : L"X86");

    if (!EnableDebugPrivilege())
        wprintf(L"!>> Unable to enable SeDebugPrivilege, functionality is limited <<!\n");

    std::vector<uint8_t> buffer(64 * 1024);
    uint32_t resLen = 0;
    auto& api = GetWow64Helper<arch>();
    while (IsBufferTooSmall(api.NtQuerySystemInformation64(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, buffer.data(), (uint32_t)buffer.size(), &resLen)))
        buffer.resize(resLen);

    typedef SYSTEM_PROCESS_INFORMATION_T<PTR_T<arch>> SPI, * PSPI;
    auto procInfo = (const PSPI)buffer.data();
    for (bool stop = false; !stop;
        stop = (procInfo->NextEntryOffset == 0), procInfo = (PSPI)((uint8_t*)procInfo + procInfo->NextEntryOffset))
    {
        if (pid != 0 && pid != (DWORD)(uint64_t)procInfo->ProcessId)
            continue;

        ScanProcessMemory<arch>(procInfo, api, issues, sensitivity, dumpDir);
    }

    return issues;
}

#if _M_AMD64
int ScanMemory(uint32_t sensitivity, uint32_t pid, const wchar_t* dumpDir)
{
    return ScanMemoryImpl<CPUArchitecture::X64>(sensitivity, pid, dumpDir);
}
#else
int ScanMemory(uint32_t sensitivity, uint32_t pid, const wchar_t* dumpDir)
{
    return (GetOSArch() == CPUArchitecture::X64 ? ScanMemoryImpl<CPUArchitecture::X64>(sensitivity, pid, dumpDir) : ScanMemoryImpl<CPUArchitecture::X86>(sensitivity, pid, dumpDir));
}
#endif
