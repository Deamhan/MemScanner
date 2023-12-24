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
#include <thread>
#include <queue>
#include <vector>

#include "file.hpp"
#include "log.hpp"
#include "memdatasource.hpp"
#include "memhelper.hpp"
#include "pe.hpp"

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
    if (!imagePath.empty())
        return false;

    try
    {
        uint64_t disp = address - moduleAddress;
        auto pe = GetOrAddImageToCache(cache, imagePath);
        if (disp > pe->GetImageSize())
            return false;

        auto rva = (uint32_t)disp;
        if (!pe->IsExecutableSectionRva(rva))
            return false;
        
        const auto& exported = pe->GetExportMap();
        auto it = exported.lower_bound(rva);
        if (it == exported.end())
            return true;

        return (it->first >= rva + size);
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

template <CPUArchitecture arch, typename SPI>
void MemoryScanner::ScanProcessMemory(SPI* procInfo, const Wow64Helper<arch>& api)
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

    std::vector<ICallbacks::AddressInfo> memAddressesToCheck;
    bool scanHookForUserAddress = false, scanRangesWithYara = false;
    auto memoryAnalysisSettings = tlsCallbacks->GetMemoryAnalysisSettings(memAddressesToCheck, scanHookForUserAddress, scanRangesWithYara);

    std::vector<uint64_t> threadsEntryPoints; 
    threadsEntryPoints.reserve(32);
    const bool threadAnanlysisEnabled = tlsCallbacks->GetThreadAnalysisSettings() != Sensitivity::Off;
    for (uint32_t i = 0; threadAnanlysisEnabled && i < procInfo->NumberOfThreads; ++i)
    {
        uint64_t startAddress = 0;
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, (DWORD)(uintptr_t)procInfo->Threads[i].ClientId.UniqueThread);
        if (hThread == nullptr)
            continue;

        std::unique_ptr<HANDLE, void(*)(HANDLE*)> threadGuard(&hThread, MemoryHelper<arch>::CloseHandleByPtr);
        if (NtSuccess(api.NtQueryInformationThread64(hThread, SystemDefinitions::THREADINFOCLASS::ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), nullptr)))
            threadsEntryPoints.push_back(startAddress);
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
                auto region = GetMemoryHelper().UpdateMemoryMapForAddr(hProcess, addrInfo.address, memoryMap);
                if (!scanRangesWithYara)
                    continue;

                if (region.BaseAddress == 0)
                    continue;

                if (region.Type == SystemDefinitions::MemType::Image && addrInfo.forceWritten)
                    requestedImageAddressToAllocBase.emplace(region.AllocationBase, addrInfo);

                std::list<std::string> yaraResults;
                ScanUsingYara(hProcess, region, yaraResults, addrInfo.address, addrInfo.size);

                if (!yaraResults.empty())
                    tlsCallbacks->OnYaraDetection(yaraResults);
            }
        }

        auto groupedMm = MemoryHelperBase::GetGroupedMemoryMap(memoryMap, [](const MemoryHelperBase::MemInfoT64& mbi) { return ((mbi.State & (PAGE_NOACCESS | PAGE_GUARD)) == 0); });

        for (const auto& group : groupedMm)
        {
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
                {
                    bool scanWithYara = false;
                    tlsCallbacks->OnSuspiciousMemoryRegionFound(group.second, threadsRelated, scanWithYara);
                    if (scanWithYara)
                    {
                        std::list<std::string> yaraResults;
                        for (const auto& region : group.second)
                            ScanUsingYara(hProcess, region, yaraResults);

                        if (!yaraResults.empty())
                            tlsCallbacks->OnYaraDetection(yaraResults);
                    }
                }
            }
            else
            {
                auto imagePath = GetMemoryHelper().GetImageNameByAddress(hProcess, group.first);
                if (imagePath.empty())
                    continue;

                for (const auto& region : group.second)
                {
                    auto protFlags = MemoryHelperBase::protToFlags(region.Protect);
                    auto suspFlags = (uint32_t)(MemoryHelperBase::WFlag | MemoryHelperBase::XFlag);
                    if ((protFlags & suspFlags) == suspFlags)
                    {
                        bool scanWithYara = false;
                        tlsCallbacks->OnWritableExecImageFound(group.second, imagePath, region, scanWithYara);
                        if (!scanWithYara)
                            continue;

                        std::list<std::string> yaraResults;
                        ScanUsingYara(hProcess, region, yaraResults);
                        if (!yaraResults.empty())
                            tlsCallbacks->OnYaraDetection(yaraResults);
                    }
                }

                if (hookAnalysisEnabled && doHookAnalysisWithMemscan)
                {
                    ReadOnlyMemoryDataSource memDs(hProcess, group.first, groupTopBorder - group.first, PAGE_SIZE);
                    
                    auto moduleArch = PE<>::GetPeArch(memDs);
                    ScanImageForHooks(moduleArch, memDs, imagePath, hooksFound);
                    auto eqRange = requestedImageAddressToAllocBase.equal_range(memDs.GetOrigin());
                    for (auto it = eqRange.first; it != eqRange.second; ++it)
                    {
                        bool privateCodeModificationFound = CheckForPrivateCodeModification(moduleArch, imagePath, memDs.GetOrigin(),
                            it->second.address, it->second.size);

                        if (privateCodeModificationFound)
                            tlsCallbacks->OnPrivateCodeModification(imagePath.c_str(), (uint32_t)(it->second.address - group.first));
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

    if (!MemoryHelper<arch>::EnableDebugPrivilege())
        GetDefaultLogger()->Log(LoggerBase::Info, L"Unable to enable SeDebugPrivilege, functionality is limited\n");

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
            ScanProcessMemory<arch>(procInfo, api);
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
                    this->ScanProcessMemory<arch>(procInfo, api);
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

bool MemoryScanner::ScanUsingYara(HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region, std::list<std::string>& result,
    uint64_t startAddress, uint64_t size)
{
    auto scanner = GetYaraScanner();
    if (scanner == nullptr)
        return false;

    ::ScanUsingYara(*scanner, hProcess, region, result, startAddress, size);
    return true;
}

bool MemoryScanner::ScanProcessUsingYara(uint32_t pid, std::list<std::string>& result)
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
