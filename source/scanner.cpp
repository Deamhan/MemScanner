#include "scanner.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <system_error>
#include <vector>

#include "file.hpp"
#include "log.hpp"
#include "memdatasource.hpp"
#include "memhelper.hpp"
#include "pe.hpp"

#undef min
#undef max

template <CPUArchitecture arch>
void CheckForHooks(DataSource& mapped, std::map<std::wstring, 
    PE<false, arch>>& parsed, std::wstring& path, std::vector<HookDescription>& result)
{
    try
    {
        PE<false, arch>* pe = nullptr;
        auto it = parsed.lower_bound(path);
        if (it != parsed.end() && it->first == path)
            pe = &it->second;
        else
        {
            it = parsed.emplace_hint(it, path, std::make_shared<File>(path.c_str()));
            pe = &it->second;
            pe->GetExportMap();
            pe->ReleaseDataSource();
        }

        return pe->CheckExportForHooks(mapped, result);
    }
    catch (const DataSourceException&)
    {}
    catch (const PeException&)
    {}
}

void MemoryScanner::DefaultCallbacks::SetDumpsRoot(const wchar_t* dumpsRoot)
{ 
    mDumpRoot = dumpsRoot;
    if (mDumpRoot.empty())
        return;

    if (*mDumpRoot.rbegin() != L'\\')
        mDumpRoot += L'\\';
}

static size_t ScanBlobForMz(const std::vector<uint8_t>& buffer, size_t offset, size_t size)
{
    for (size_t i = offset; i < size - 1; ++i)
    {
        if (*(uint16_t*)(buffer.data() + i) == 0x5a4d)
            return i;
    }

    return size;
}

static const wchar_t* CpuArchToString(CPUArchitecture arch)
{
    switch (arch)
    {
    case CPUArchitecture::X86:
        return L"x86";
    case CPUArchitecture::X64:
        return L"x64";
    default:
        return L"Unknown";
    }
}

static std::pair<uint64_t, CPUArchitecture> ScanRegionForPE(HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region)
{
    ReadOnlyMemoryDataSource memory(hProcess, region.BaseAddress, region.RegionSize);
    std::vector<uint8_t> buffer(64 * 1024);
    for (uint64_t offs = 0; offs < region.RegionSize; offs += buffer.size())
    {
        try
        {
            auto read = (size_t)std::min<uint64_t>(buffer.size(), region.RegionSize - offs);
            memory.Read(offs, buffer.data(), read);
            size_t mzPos = ScanBlobForMz(buffer, 0, read);
            if (mzPos == read)
                break;

            DataSourceFragment fragment(memory, mzPos);
            auto arch = PE<>::GetPeArch(fragment);
            if (arch != CPUArchitecture::Unknown)
                return  { fragment.GetOrigin(), arch };
        }
        catch (const DataSourceException&)
        {
        }
    }

    return { 0, CPUArchitecture::Unknown };
}

void MemoryScanner::DefaultCallbacks::OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT& continiousRegions,
    const std::vector<uint64_t>& threadEntryPoints)
{
    GetDefaultLogger()->Log(ILogger::Info, L"\tSuspicious memory region:\n");
    for (const auto& region : continiousRegions)
        printMBI<uint64_t>(region, L"\t\t");

    if (!threadEntryPoints.empty())
    {
        GetDefaultLogger()->Log(ILogger::Info, L"\t\tRelated threads:\n");
        for (const auto threadEP : threadEntryPoints)
            GetDefaultLogger()->Log(ILogger::Info, L"\t\t\t0x%llx\n", (unsigned long long)threadEP);

        GetDefaultLogger()->Log(ILogger::Info, L"\n");
    }

    bool isPeFound = false;
    for (const auto& region : continiousRegions)
    {
        auto peFound = ScanRegionForPE(mProcess, region);
        if (peFound.first != 0)
        {
            GetDefaultLogger()->Log(ILogger::Info, L"\t\tPE (%s) found: 0x%llx\n", CpuArchToString(peFound.second),
                (unsigned long long)peFound.first);
            isPeFound = true;
        }
    }

    if (isPeFound)
        GetDefaultLogger()->Log(ILogger::Info, L"\n");

    if (mDumpRoot.empty())
        return;

    std::wstring processDumpDir = mDumpRoot;
    wchar_t buffer[64] = {};
    _snwprintf_s(buffer, _countof(buffer), L"_%u_%llu", (unsigned)mCurrentPid, (unsigned long long)mProcessCreationTime.QuadPart);
    processDumpDir.append(mProcessName).append(buffer);

    if (!CreateDirectoryW(processDumpDir.c_str(), nullptr))
        GetDefaultLogger()->Log(ILogger::Error, L"\tUnable to create directory %s:\n", processDumpDir.c_str());

    for (const auto& region : continiousRegions)
    {
        ReadOnlyMemoryDataSource dsToDump(mProcess, region.BaseAddress, region.RegionSize);
        std::wstring dumpPath = processDumpDir;
        _snwprintf_s(buffer, _countof(buffer), L"\\%llx.bin", (unsigned long long)region.BaseAddress);
        dumpPath.append(buffer);
        File dump(dumpPath.c_str(), File::CreateNew, 0);
        dsToDump.Dump(dump, 0, region.RegionSize, 64 * 1024, true);

        RegisterNewDump(region, dumpPath);
    }
}

void MemoryScanner::DefaultCallbacks::OnHooksFound(const std::vector<HookDescription>& hooks, const wchar_t* imageName)
{
    GetDefaultLogger()->Log(ILogger::Info, L"\tHooks for %s:\n", imageName);
    for (const auto& hook : hooks)
    {
        for (const auto& name : hook.functionDescription->names)
            GetDefaultLogger()->Log(ILogger::Info, L"\t\t%S\n", name.c_str());
        
        GetDefaultLogger()->Log(ILogger::Info, L"\t\tOrdinal: %d\n\n", hook.functionDescription->ordinal);
    }
}

void MemoryScanner::DefaultCallbacks::OnProcessScanBegin(uint32_t processId, LARGE_INTEGER creationTime, HANDLE hProcess, const std::wstring& processName)
{
    if (hProcess == nullptr)
    {
        GetDefaultLogger()->Log(ILogger::Error, L"Process %s [PID = %u, CreateTime = %llu]: unable to open\n", processName.c_str(),
            (unsigned)processId, (unsigned long long)creationTime.QuadPart);
        return;
    }

    GetDefaultLogger()->Log(ILogger::Info, L"Process %s [PID = %u, CreateTime = %llu]\n", processName.c_str(),
        (unsigned)processId, (unsigned long long)creationTime.QuadPart);

    mCurrentPid = processId;
    mProcessName = processName;
    mProcess = hProcess;
}

void MemoryScanner::DefaultCallbacks::OnProcessScanEnd()
{
    if (mProcess != 0)
        GetDefaultLogger()->Log(ILogger::Info, L"Process [PID = %u]: done\n", mCurrentPid);
}

class ProcessScanGuard
{
public:
    ProcessScanGuard(MemoryScanner::ICallbacks* callbacks) : mCallbacks(callbacks)
    {}

    ~ProcessScanGuard()
    {
        mCallbacks->OnProcessScanEnd();
    }

private:
    MemoryScanner::ICallbacks* mCallbacks;
};

template <CPUArchitecture arch, typename SPI>
void MemoryScanner::ScanProcessMemory(SPI* procInfo, const Wow64Helper<arch>& api)
{
    DWORD pid = (DWORD)(uint64_t)procInfo->ProcessId;
    std::wstring name((const wchar_t*)procInfo->ImageName.Buffer, procInfo->ImageName.Length / sizeof(wchar_t));

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    mCallbacks->OnProcessScanBegin(pid, procInfo->CreateTime, hProcess, name);
    ProcessScanGuard scanGuard{ mCallbacks.get() };

    if (hProcess == nullptr)
        return;

    std::vector<PTR_T<arch>> threadsEntryPoints;
    std::unique_ptr<HANDLE, void(*)(HANDLE*)> processGuard(&hProcess, MemoryHelper<arch>::CloseHandleByPtr);
    for (uint32_t i = 0; i < procInfo->NumberOfThreads; ++i)
    {
        PTR_T<arch> startAddress = 0;
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, (DWORD)(uintptr_t)procInfo->Threads[i].ClientId.UniqueThread);
        if (hThread == nullptr)
            continue;

        std::unique_ptr<HANDLE, void(*)(HANDLE*)> threadGuard(&hThread, MemoryHelper<arch>::CloseHandleByPtr);
        if (NtSuccess(api.NtQueryInformationThread64(hThread, SystemDefinitions::THREADINFOCLASS::ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), nullptr)))
            threadsEntryPoints.push_back(startAddress);
    }

    auto mm = GetMemoryHelper().GetMemoryMap(hProcess);
    auto groupedMm = MemoryHelperBase::GetGroupedMemoryMap(mm, [](const typename MemoryHelperBase::MemInfoT64& mbi) { return ((mbi.State & (PAGE_NOACCESS | PAGE_GUARD)) == 0); });

    std::vector<HookDescription> hooksFound;
    hooksFound.reserve(30); // should be enough

    for (const auto& group : groupedMm)
    {
        uint32_t allocProtMask = 0, protMask = 0;
        switch (mSensitivity)
        {
        case Low:
            protMask = (MemoryHelperBase::WFlag | MemoryHelperBase::XFlag);
            break;
        case Medium:
            protMask = MemoryHelperBase::XFlag;
            break;
        default:
        case High:
            allocProtMask = protMask = MemoryHelperBase::XFlag;
            break;
        }

        const auto lastInGroup = group.second.rbegin();
        auto groupTopBorder = lastInGroup->BaseAddress + lastInGroup->RegionSize;
        if (lastInGroup->Type != SystemDefinitions::MemType::Image)
        {
            bool isSuspGroup = false;
            for (const auto& region : group.second)
            {
                bool allocProtRes = (allocProtMask != 0 ? (MemoryHelperBase::protToFlags(region.AllocationProtect) & allocProtMask) == allocProtMask : false);
                bool protRes = (protMask != 0 ? (MemoryHelperBase::protToFlags(region.Protect) & protMask) == protMask : false);
                isSuspGroup = protRes || allocProtRes;
            }

            std::vector<uint64_t> threadsRelated;
            for (const auto threadEP : threadsEntryPoints)
            {
                if (group.first <= threadEP && threadEP < groupTopBorder)
                    threadsRelated.push_back(threadEP);
            }

            if (isSuspGroup || !threadsRelated.empty())
                mCallbacks->OnSuspiciousMemoryRegionFound(group.second, threadsRelated);
        }
        else
        {
            ReadOnlyMemoryDataSource memDs(hProcess, group.first, groupTopBorder - group.first, PAGE_SIZE);
            auto imagePath = GetMemoryHelper().GetImageNameByAddress(hProcess, memDs.GetOrigin());

            if (imagePath.empty())
                continue;

            
            switch (PE<>::GetPeArch(memDs))
            {
            case CPUArchitecture::X86:
                CheckForHooks<CPUArchitecture::X86>(memDs, mCached32, imagePath, hooksFound);
                break;
            case CPUArchitecture::X64:
                CheckForHooks<CPUArchitecture::X64>(memDs, mCached64, imagePath, hooksFound);
                break;
            }

            if (!hooksFound.empty())
                mCallbacks->OnHooksFound(hooksFound, imagePath.c_str());
        }
    }
}

template <CPUArchitecture arch>
void MemoryScanner::ScanMemoryImpl(uint32_t pid)
{
    if (!MemoryHelper<arch>::EnableDebugPrivilege())
        GetDefaultLogger()->Log(ILogger::Info, L"!>> Unable to enable SeDebugPrivilege, functionality is limited <<!\n");

    std::vector<uint8_t> buffer(64 * 1024);
    uint32_t resLen = 0;
    auto& api = GetWow64Helper<arch>();
    while (IsBufferTooSmall(api.NtQuerySystemInformation64(SystemDefinitions::SYSTEM_INFORMATION_CLASS::SystemProcessInformation, buffer.data(), (uint32_t)buffer.size(), &resLen)))
        buffer.resize(resLen);

    typedef SystemDefinitions::SYSTEM_PROCESS_INFORMATION_T<PTR_T<arch>> SPI, * PSPI;
    auto procInfo = (const PSPI)buffer.data();
    for (bool stop = false; !stop;
        stop = (procInfo->NextEntryOffset == 0), procInfo = (PSPI)((uint8_t*)procInfo + procInfo->NextEntryOffset))
    {
        if (pid != 0 && pid != (DWORD)(uint64_t)procInfo->ProcessId)
            continue;

        ScanProcessMemory<arch>(procInfo, api);
    }
}

void MemoryScanner::Scan(uint32_t pid)
{
#if _M_AMD64
    ScanMemoryImpl<CPUArchitecture::X64>(pid);
#else
    if (GetOSArch() == CPUArchitecture::X64)
        ScanMemoryImpl<CPUArchitecture::X64>(pid);
    else
        ScanMemoryImpl<CPUArchitecture::X86>(pid);
#endif
}
