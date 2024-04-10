#include "stdafx.h"

#include "../include/scanner.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <system_error>
#include <thread>
#include <queue>
#include <vector>

#include "../include/file.hpp"
#include "../include/log.hpp"
#include "../include/memdatasource.hpp"
#include "../include/memhelper.hpp"
#include "../include/pe.hpp"

#undef min
#undef max

thread_local MemoryScanner::ICallbacks* MemoryScanner::tlsCallbacks;
thread_local std::unique_ptr<YaraScanner> MemoryScanner::tlsYaraScanner;

class TlsScannerCleaner
{
public:
    TlsScannerCleaner() = default;
    ~TlsScannerCleaner()
    {
        MemoryScanner::ResetYaraScannerForThread();
    }
};

template <CPUArchitecture arch>
static PE<false, arch>* GetOrAddImageToCache(std::pair<std::map<std::wstring, PE<false, arch>>, std::mutex>& cache,
    const std::wstring& path)
{
    auto& parsed = cache.first;
    auto& lock = cache.second;

    std::lock_guard<std::mutex> guard(lock);

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

    return pe;
}

template <CPUArchitecture arch>
static void CheckForHooks(DataSource& mapped, std::pair<std::map<std::wstring, PE<false, arch>>,std::mutex>& cache,
    const std::wstring& path, std::vector<HookDescription>& result)
{
    try
    {
        auto pe = GetOrAddImageToCache(cache, path);
        pe->CheckExportForHooks(mapped, result);
    }
    catch (const DataSourceException&)
    {}
    catch (const PeException&)
    {}
}

template <CPUArchitecture arch>
static bool CheckForPrivateCodeModificationForArch(const std::wstring& imagePath, std::pair<std::map<std::wstring, PE<false, arch>>,
    std::mutex>& cache, uint64_t moduleAddress, uint64_t address, uint64_t size)
{
    if (imagePath.empty())
        return false;

    try
    {
        uint64_t disp = address - moduleAddress;
        auto pe = GetOrAddImageToCache(cache, imagePath);
        if (disp > pe->GetImageSize())
            return false;

        auto rva = (uint32_t)disp;
        if (!pe->IsExecutableRange(rva, (uint32_t)size))
            return false;
        
        const auto& exported = pe->GetExportMap();
        auto it = exported.lower_bound(rva);
        if (it == exported.end())
            return true;

        return (it->first > rva);
    }
    catch (const DataSourceException&)
    {
    }
    catch (const PeException&)
    {
    }

    return false;
}

class ProcessScanGuard
{
public:
    ProcessScanGuard(MemoryScanner::ICallbacks* scanCallbacks) : tlsCallbacks(scanCallbacks)
    {}

    ~ProcessScanGuard()
    {
        tlsCallbacks->OnProcessScanEnd();
    }

private:
    MemoryScanner::ICallbacks* tlsCallbacks;
};

template <CPUArchitecture arch>
static void QueryThreadEntryPoints(const std::vector<DWORD>& threads, std::vector<uint64_t>& threadsEntryPoints, const Wow64Helper<arch>& api)
{
    for (auto threadId : threads)
    {
        uint64_t startAddress = 0;
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
        if (hThread == nullptr)
            continue;

        std::unique_ptr<HANDLE, void(*)(HANDLE*)> threadGuard(&hThread, MemoryHelper<arch>::CloseHandleByPtr);
        if (NtSuccess(api.NtQueryInformationThread64(hThread, SystemDefinitions::THREADINFOCLASS::ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), nullptr)))
            threadsEntryPoints.push_back(startAddress);
    }
}

static bool IsCodeStartOperation(OperationType operation)
{
    switch (operation)
    {
    case OperationType::CreateThread:
    case OperationType::Apc:
        return true;
    default:
        return false;
    }
}

template <CPUArchitecture arch>
void MemoryScanner::ScanProcessMemoryImpl(HANDLE hProcess, const std::vector<DWORD>& threads, const Wow64Helper<arch>& api)
{
    std::vector<ICallbacks::AddressInfo> memAddressesToCheck;
    bool scanHookForUserAddress = false, scanRangesWithYara = false;
    auto memoryAnalysisSettings = tlsCallbacks->GetMemoryAnalysisSettings(memAddressesToCheck, scanHookForUserAddress, scanRangesWithYara);

    std::vector<uint64_t> codeEntryPoints;
    const bool threadAnalysisEnabled = tlsCallbacks->GetThreadAnalysisSettings() != Sensitivity::Off;
    if (!threads.empty() && threadAnalysisEnabled)
    {
        codeEntryPoints.reserve(threads.size());
        QueryThreadEntryPoints<arch>(threads, codeEntryPoints, api);
    }
    
    std::vector<HookDescription> hooksFound;
    hooksFound.reserve(30); // should be enough

    std::multimap<uint64_t, ICallbacks::AddressInfo> requestedImageAddressToAllocBase;

    bool hookAnalysisEnabled = tlsCallbacks->GetHookAnalysisSettings() != Sensitivity::Off;
    bool doHookAnalysisWithMemscan = true;
    if (memoryAnalysisSettings != Sensitivity::Off)
    {
        MemoryHelperBase::MemoryMapT memoryMap;
        if (memAddressesToCheck.empty())
            memoryMap = GetMemoryHelper().GetMemoryMap(hProcess);
        else
        {
            doHookAnalysisWithMemscan = scanHookForUserAddress;
            for (const auto& addrInfo : memAddressesToCheck)
            {
                bool isAlignedAllocation = false;

                MemoryHelperBase::MemoryMapConstIteratorT rangeBegin, rangeEnd;
                auto region = GetMemoryHelper().UpdateMemoryMapForAddr(hProcess, addrInfo.address, memoryMap, 
                    rangeBegin, rangeEnd, isAlignedAllocation);
                if (!scanRangesWithYara)
                    continue;

                if (region.BaseAddress == 0)
                    continue;

                if (!tlsCallbacks->OnExplicitAddressScan(region, rangeBegin, rangeEnd, isAlignedAllocation, addrInfo))
                    continue;

                bool isImageRegion = (region.Type == SystemDefinitions::MemType::Image);
                bool imageOverwrite = isImageRegion && addrInfo.operation == OperationType::Write;
                if (imageOverwrite)
                    requestedImageAddressToAllocBase.emplace(region.AllocationBase, addrInfo);

                if (threadAnalysisEnabled && IsCodeStartOperation(addrInfo.operation))
                    codeEntryPoints.push_back(addrInfo.address);

                ScanUsingYara(hProcess, region, addrInfo.address, addrInfo.size, addrInfo.operation, addrInfo.externalOperation,
                    isAlignedAllocation);
            }
        }

        uint32_t allocProtMask = 0, protMask = 0;
        switch (memoryAnalysisSettings)
        {
        case Sensitivity::Low:
            protMask = (MemoryHelperBase::WFlag | MemoryHelperBase::XFlag);
            break;
        case Sensitivity::Medium:
            protMask = MemoryHelperBase::XFlag;
            break;
        default:
        case Sensitivity::High:
            allocProtMask = protMask = MemoryHelperBase::XFlag;
            break;
        }

        auto groupedMm = MemoryHelperBase::GetGroupedMemoryMap(memoryMap, [](const MemoryHelperBase::MemInfoT64&) { return true; });

        for (const auto& group : groupedMm)
        {
            auto groupTopBorder = MemoryHelperBase::GetTopReadableBorder(group.second);
            if (group.second.begin()->Type != SystemDefinitions::MemType::Image)
            {
                bool isSuspGroup = false;
                for (const auto& region : group.second)
                {
                    if (!MemoryHelperBase::IsReadableRegion(region))
                        continue;

                    bool allocProtRes = (allocProtMask != 0 ? (MemoryHelperBase::protToFlags(region.AllocationProtect) & allocProtMask) == allocProtMask : false);
                    bool protRes = (protMask != 0 ? (MemoryHelperBase::protToFlags(region.Protect) & protMask) == protMask : false);
                    isSuspGroup = protRes || allocProtRes;
                }

                std::vector<uint64_t> codeEpRelated;
                for (const auto codeEP : codeEntryPoints)
                {
                    if (group.first <= codeEP && codeEP < groupTopBorder)
                        codeEpRelated.push_back(codeEP);
                }

                if (isSuspGroup || !codeEpRelated.empty())
                {
                    bool scanWithYara = false;
                    tlsCallbacks->OnSuspiciousMemoryRegionFound(group.second, codeEpRelated, scanWithYara);
                    if (scanWithYara)
                    {
                        bool isAlignedAllocation = MemoryHelperBase::IsAlignedAllocation(group.second);
                        for (const auto& region : group.second)
                        {
                            if (!MemoryHelperBase::IsReadableRegion(region))
                                continue;

                            ScanUsingYara(hProcess, region, 0, 0, OperationType::Unknown, false, isAlignedAllocation);
                        }
                    }
                }
            }
            else
            {
                SystemDefinitions::NT_STATUS status;
                auto imagePath = GetMemoryHelper().GetImageNameByAddress(hProcess, group.first, &status);
                if (imagePath.empty())
                {
                    if (status == SystemDefinitions::NT_STATUS::StatusFileDeleted)
                        tlsCallbacks->OnDoppelgangingFound(group.first);

                    continue;
                }

                for (const auto& region : group.second)
                {
                    if (!MemoryHelperBase::IsReadableRegion(region))
                        continue;

                    auto protFlags = MemoryHelperBase::protToFlags(region.Protect);
                    auto suspFlags = (uint32_t)(MemoryHelperBase::WFlag | MemoryHelperBase::XFlag);
                    if ((protFlags & suspFlags) == suspFlags)
                    {
                        bool scanWithYara = false;
                        tlsCallbacks->OnWritableExecImageFound(group.second, imagePath, region, scanWithYara);
                        if (!scanWithYara)
                            continue;

                        ScanUsingYara(hProcess, region);
                    }
                }

                if (hookAnalysisEnabled && doHookAnalysisWithMemscan)
                {
                    ReadOnlyMemoryDataSource memDs(hProcess, group.first, groupTopBorder - group.first, PAGE_SIZE);

                    auto moduleArch = PE<>::GetPeArch(memDs);
                    ScanImageForHooks(moduleArch, memDs, imagePath, hooksFound);
                    if (!hooksFound.empty())
                    {
                        bool isKnown = false;
                        if (GetMemoryHelper().IsModuleKnownByPeb(hProcess, group.first, isKnown) && !isKnown)
                            tlsCallbacks->OnHiddenImage(imagePath.c_str(), group.first);
                    }

                    auto eqRange = requestedImageAddressToAllocBase.equal_range(memDs.GetOrigin());
                    for (auto it = eqRange.first; it != eqRange.second; ++it)
                    {
                        auto rva = (uint32_t)(it->second.address - group.first);
                        bool privateCodeModificationFound = CheckForPrivateCodeModification(moduleArch, imagePath, memDs.GetOrigin(),
                            it->second.address, it->second.size);

                        if (privateCodeModificationFound)
                            tlsCallbacks->OnPrivateCodeModification(imagePath.c_str(), group.first, rva, (uint32_t)it->second.size);

                        bool imageHeadersModification = it->second.address < group.first + PAGE_SIZE;
                        if (imageHeadersModification)
                            tlsCallbacks->OnImageHeadersModification(imagePath.c_str(), group.first, rva, (uint32_t)it->second.size);
                    }
                }
            }
        }
    }

    if (hookAnalysisEnabled && !doHookAnalysisWithMemscan)
    {
        auto loadedImages = GetMemoryHelper().GetImageDataFromPeb(hProcess);
        for (const auto& image : loadedImages)
        {
            ReadOnlyMemoryDataSource memDs(hProcess, image.BaseAddress, image.ImageSize, PAGE_SIZE);
            ScanImageForHooks(image.Architecture, memDs, image.ImagePath, hooksFound);
        }
    }
}


class DegugPrivelegeEnabler
{
public:
    DegugPrivelegeEnabler() noexcept
    {
        mPrivilegeEnabled = MemoryHelperBase::EnableDebugPrivilege();
    }

    bool IsPrivelegeEnabled() const noexcept { return mPrivilegeEnabled; }

private:
    bool mPrivilegeEnabled;
};

static DegugPrivelegeEnabler gDebugPrivilegeEnabler;

void MemoryScanner::ValidateTokenPrivileges()
{
    if (!gDebugPrivilegeEnabler.IsPrivelegeEnabled())
        GetDefaultLogger()->Log(LoggerBase::Info, L"Unable to enable SeDebugPrivilege, functionality is limited" LOG_ENDLINE_STR);
}

template <CPUArchitecture arch>
void MemoryScanner::ScanProcessMemoryImpl(const TargetProcessInformation& targetProcess, ICallbacks* scanCallbacks)
{
    TlsScannerCleaner scannerCleaner;
    tlsCallbacks = scanCallbacks;

    auto& memLogger = MemoryLogger::GetInstance();
    MemoryLogger::AutoFlush flusher(memLogger);
    SetThreadLocalDefaultLogger(&memLogger); // there can be a lot of threads execiting current routine in parallel

    ValidateTokenPrivileges();

    HANDLE hProcess = targetProcess.processHandle;
    uint32_t pid = targetProcess.processId;
    std::unique_ptr<HANDLE, void(*)(HANDLE*)> processGuard(nullptr, MemoryHelper<arch>::CloseHandleByPtr);
    if (hProcess == nullptr)
    {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        processGuard.reset(&hProcess);
    }

    LARGE_INTEGER createTime = targetProcess.createTime;
    std::wstring processName = targetProcess.processMainExecPath != nullptr ? targetProcess.processMainExecPath : L"";
    if (hProcess == nullptr)
    {
        tlsCallbacks->OnProcessScanBegin(pid, createTime, hProcess, processName); // notifies client about open failure (hProcess is nullptr)
        return;
    }

    auto& api = GetWow64Helper<arch>();
    if (createTime.QuadPart == 0 && !api.QueryProcessCreateTime(hProcess, createTime))
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Error, L"Unable to query creation time for process [PID = %u]" LOG_ENDLINE_STR,
            (unsigned)pid);
        return; // no unique process identification, leaving
    }

    if (processName.empty())
        processName = api.QueryProcessName(hProcess); // even if it fails we can work without it
    else
        processName = IWow64Helper::QueryProcessNameByMainExecutablePath(processName);

    tlsCallbacks->OnProcessScanBegin(pid, createTime, hProcess, processName);
    ProcessScanGuard scanGuard{ tlsCallbacks };

    ScanProcessMemoryImpl(hProcess, std::vector<DWORD>{}, api);
}

template <CPUArchitecture arch, typename SPI>
void MemoryScanner::ScanProcessMemoryImpl(SPI* procInfo, const Wow64Helper<arch>& api)
{
    DWORD pid = (DWORD)(uint64_t)procInfo->ProcessId;
    std::wstring processName((const wchar_t*)procInfo->ImageName.Buffer, procInfo->ImageName.Length / sizeof(wchar_t));
    auto createTime = procInfo->CreateTime;
    
    if (tlsCallbacks->SkipProcess(pid, createTime, processName))
        return;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    std::unique_ptr<HANDLE, void(*)(HANDLE*)> processGuard(&hProcess, MemoryHelper<arch>::CloseHandleByPtr);

    tlsCallbacks->OnProcessScanBegin(pid, createTime, hProcess, processName);
    ProcessScanGuard scanGuard{ tlsCallbacks };

    if (hProcess == nullptr)
        return;

    std::vector<DWORD> threads(procInfo->NumberOfThreads);
    for (uint32_t i = 0; i < procInfo->NumberOfThreads; ++i)
        threads[i] = (DWORD)(uintptr_t)procInfo->Threads[i].ClientId.UniqueThread;

    ScanProcessMemoryImpl(hProcess, threads, api);
}

void MemoryScanner::ScanImageForHooks(CPUArchitecture arch, DataSource& ds, const std::wstring& imageName, 
    std::vector<HookDescription>& hooksFound)
{
    switch (arch)
    {
    case CPUArchitecture::X86:
        CheckForHooks<CPUArchitecture::X86>(ds, mCached32, imageName, hooksFound);
        break;
    case CPUArchitecture::X64:
        CheckForHooks<CPUArchitecture::X64>(ds, mCached64, imageName, hooksFound);
        break;
    }

    if (!hooksFound.empty())
        tlsCallbacks->OnHooksFound(hooksFound, imageName.c_str());
}

bool MemoryScanner::CheckForPrivateCodeModification(CPUArchitecture arch, const std::wstring& imagePath, uint64_t moduleAddress,
    uint64_t address, uint64_t size)
{
    bool result = false;
    switch (arch)
    {
    case CPUArchitecture::X86:
        result = CheckForPrivateCodeModificationForArch<CPUArchitecture::X86>(imagePath, mCached32, moduleAddress, address, size);
        break;
    case CPUArchitecture::X64:
        result = CheckForPrivateCodeModificationForArch<CPUArchitecture::X64>(imagePath, mCached64, moduleAddress, address, size);
        break;
    }

    return result;
}

class SimpleThreadPool
{
public:
    SimpleThreadPool(uint32_t amountOfThreads) : 
        mThreads(amountOfThreads != 0 ? amountOfThreads : std::thread::hardware_concurrency())
    {}

    template <class Func, class... Args>
    void Execute(Func&& func, Args&&... args)
    {
        for (auto& t : mThreads)
            t = std::thread(std::forward<Func>(func), std::forward<Args>(args)...);

        for (auto& t : mThreads)
            t.join();
    }

protected:
    std::vector<std::thread> mThreads;
};

template <CPUArchitecture arch>
void MemoryScanner::ScanMemoryImpl(uint32_t workersCount, MemoryScanner::ICallbacks* scanCallbacks)
{
    TlsScannerCleaner scannerCleaner;
    tlsCallbacks = scanCallbacks;

    auto& memLogger = MemoryLogger::GetInstance();
    MemoryLogger::AutoFlush flusher(memLogger);
    SetThreadLocalDefaultLogger(&memLogger); // there can be a lot of threads execiting current routine in parallel

    ValidateTokenPrivileges();

    std::vector<uint8_t> buffer(64 * 1024);
    uint32_t resLen = 0;
    auto& api = GetWow64Helper<arch>();
    while (IsBufferTooSmall(api.NtQuerySystemInformation64(SystemDefinitions::SYSTEM_INFORMATION_CLASS::SystemProcessInformation, buffer.data(), (uint32_t)buffer.size(), &resLen)))
        buffer.resize(resLen);

    typedef SystemDefinitions::SYSTEM_PROCESS_INFORMATION_T<PTR_T<arch>> SPI, * PSPI;
    auto procInfo = (const PSPI)buffer.data();

    std::queue<PSPI> processInfoParsed;
    bool isSingleThreaded = workersCount == 1;

    for (bool stop = false; !stop;
        stop = (procInfo->NextEntryOffset == 0), procInfo = (PSPI)((uint8_t*)procInfo + procInfo->NextEntryOffset))
    {
        auto pid = (DWORD)(uint64_t)procInfo->ProcessId;
        if (pid == 0 || pid == 4)
            continue;

        if (isSingleThreaded)
            ScanProcessMemoryImpl<arch>(procInfo, api);
        else
            processInfoParsed.push(procInfo);
    }

    if (isSingleThreaded)
        return;

    std::mutex lock;
    auto workerProc = [&processInfoParsed, &lock, &api, this, scanCallbacks]()
        {
            TlsScannerCleaner scannerCleaner;
            tlsCallbacks = scanCallbacks;

            auto& memLogger = MemoryLogger::GetInstance();
            MemoryLogger::AutoFlush flusher(memLogger);
            SetThreadLocalDefaultLogger(&memLogger);

            while (true)
            {
                PSPI procInfo = nullptr;
                {
                    std::lock_guard<std::mutex> guard(lock);

                    if (processInfoParsed.empty())
                        return;

                    procInfo = processInfoParsed.front();
                    processInfoParsed.pop();
                }

                try
                {
                    this->ScanProcessMemoryImpl<arch>(procInfo, api);
                }
                catch (const std::exception& e)
                {
                    GetDefaultLoggerForThread()->Log(LoggerBase::Error, L"Unhandled exception: %S\n", e.what());
                }
            }
        };

    SimpleThreadPool pool(workersCount);
    pool.Execute(workerProc);
}

void MemoryScanner::Scan(std::shared_ptr<MemoryScanner::ICallbacks> scanCallbacks, uint32_t workersCount)
{
#if _M_AMD64
    ScanMemoryImpl<CPUArchitecture::X64>(workersCount, scanCallbacks.get());
#else
    if (GetOSArch() == CPUArchitecture::X64)
        ScanMemoryImpl<CPUArchitecture::X64>(workersCount, scanCallbacks.get());
    else
        ScanMemoryImpl<CPUArchitecture::X86>(workersCount, scanCallbacks.get());
#endif
}

void MemoryScanner::Scan(const TargetProcessInformation& targetProcess, std::shared_ptr<ICallbacks> scanCallbacks)
{
#if _M_AMD64
    ScanProcessMemoryImpl<CPUArchitecture::X64>(targetProcess, scanCallbacks.get());
#else
    if (GetOSArch() == CPUArchitecture::X64)
        ScanProcessMemoryImpl<CPUArchitecture::X64>(targetProcess, scanCallbacks.get());
    else
        ScanProcessMemoryImpl<CPUArchitecture::X86>(targetProcess, scanCallbacks.get());
#endif
}

YaraScanner* MemoryScanner::GetYaraScanner()
{
    if (tlsYaraScanner || !mYaraRules)
        return tlsYaraScanner.get();

    std::lock_guard<std::mutex> lg(mYaraRulesLock);
    tlsYaraScanner = std::make_unique<YaraScanner>(mYaraRules);
    return tlsYaraScanner.get();
}

void MemoryScanner::SetYaraRules(std::shared_ptr<YaraScanner::YaraRules> rules)
{ 
    std::lock_guard<std::mutex> lg(mYaraRulesLock);
    mYaraRules = std::move(rules);
}

void MemoryScanner::SetYaraRules(const std::list<std::string>& rules)
{
    SetYaraRules(std::make_shared<YaraScanner::YaraRules>(rules));
}

void MemoryScanner::SetYaraRules(const wchar_t* rulesDirectory)
{
    SetYaraRules(std::make_shared<YaraScanner::YaraRules>(rulesDirectory));
}

bool MemoryScanner::ScanUsingYara(HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region, uint64_t startAddress,
    uint64_t size, OperationType operation, bool externalOperation, bool isAlignedAllocation)
{
    auto scanner = GetYaraScanner();
    if (scanner == nullptr)
    {
        // we still need to notify about scanning attempt
        tlsCallbacks->OnYaraScan(region, startAddress, size, externalOperation, operation, isAlignedAllocation, nullptr);
        return false;
    }

    std::set<std::string> yaraResults;
    ::ScanUsingYara(*scanner, hProcess, region, yaraResults, startAddress, size, operation, externalOperation, isAlignedAllocation);
    tlsCallbacks->OnYaraScan(region, startAddress, size, externalOperation, operation, isAlignedAllocation, &yaraResults);

    return true;
}

bool MemoryScanner::ScanProcessUsingYara(uint32_t pid, std::set<std::string>& result)
{
    auto scanner = GetYaraScanner();
    if (scanner == nullptr)
        return false;

    ::ScanProcessUsingYara(*scanner, pid, result);
    return true;
}

MemoryScanner& MemoryScanner::GetInstance()
{
    static MemoryScanner scanner;
    return scanner;
}
