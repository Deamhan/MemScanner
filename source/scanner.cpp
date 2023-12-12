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

thread_local MemoryScanner::ICallbacks* MemoryScanner::callbacks;

template <CPUArchitecture arch>
PE<false, arch>* GetOrAddImageToCache(std::pair<std::map<std::wstring, PE<false, arch>>, std::mutex>& cache,
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
void CheckForHooks(DataSource& mapped, std::pair<std::map<std::wstring, PE<false, arch>>,std::mutex>& cache,
    const std::wstring& path, std::vector<HookDescription>& result)
{
    try
    {
        auto pe = GetOrAddImageToCache(cache, path);
        return pe->CheckExportForHooks(mapped, result);
    }
    catch (const DataSourceException&)
    {}
    catch (const PeException&)
    {}
}

class ProcessScanGuard
{
public:
    ProcessScanGuard(MemoryScanner::ICallbacks* scanCallbacks) : callbacks(scanCallbacks)
    {}

    ~ProcessScanGuard()
    {
        callbacks->OnProcessScanEnd();
    }

private:
    MemoryScanner::ICallbacks* callbacks;
};

template <CPUArchitecture arch, typename SPI>
void MemoryScanner::ScanProcessMemory(SPI* procInfo, const Wow64Helper<arch>& api)
{
    DWORD pid = (DWORD)(uint64_t)procInfo->ProcessId;
    std::wstring processName((const wchar_t*)procInfo->ImageName.Buffer, procInfo->ImageName.Length / sizeof(wchar_t));
    auto createTime = procInfo->CreateTime;
    
    if (callbacks->SkipProcess(pid, createTime, processName))
        return;
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    std::unique_ptr<HANDLE, void(*)(HANDLE*)> processGuard(&hProcess, MemoryHelper<arch>::CloseHandleByPtr);

    callbacks->OnProcessScanBegin(pid, createTime, hProcess, processName);
    ProcessScanGuard scanGuard{ callbacks };

    if (hProcess == nullptr)
        return;

    std::vector<uint64_t> memAddressesToCheck;
    bool scanHookForUserAddress = false;
    auto memoryAnalysisSettings = callbacks->GetMemoryAnalysisSettings(memAddressesToCheck, scanHookForUserAddress);

    std::vector<uint64_t> threadsEntryPoints; 
    threadsEntryPoints.reserve(32);
    const bool threadAnanlysisEnabled = callbacks->GetThreadAnalysisSettings() != Sensitivity::Off;
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

    bool hookAnalysisEnabled = callbacks->GetHookAnalysisSettings() != Sensitivity::Off;
    bool doHookAnalysisWithMemscan = true;
    if (memoryAnalysisSettings != Sensitivity::Off)
    {
        MemoryHelperBase::MemoryMapT memoryMap;
        if (memAddressesToCheck.empty())
            memoryMap = GetMemoryHelper().GetMemoryMap(hProcess);
        else
        {
            doHookAnalysisWithMemscan = scanHookForUserAddress;
            for (auto addr : memAddressesToCheck)
                GetMemoryHelper().UpdateMemoryMapForAddr(hProcess, addr, memoryMap);
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
                    callbacks->OnSuspiciousMemoryRegionFound(group.second, threadsRelated);
            }
            else if (hookAnalysisEnabled && doHookAnalysisWithMemscan)
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
                    callbacks->OnHooksFound(hooksFound, imagePath.c_str());
            }
        }
    }

    if (hookAnalysisEnabled && !doHookAnalysisWithMemscan)
    {
        auto loadedImages = GetMemoryHelper().GetImageDataFromPeb(hProcess);
        for (const auto& image : loadedImages)
        {
            ReadOnlyMemoryDataSource memDs(hProcess, image.BaseAddress, image.ImageSize, PAGE_SIZE);

            switch (image.Architecture)
            {
            case CPUArchitecture::X86:
                CheckForHooks<CPUArchitecture::X86>(memDs, mCached32, image.ImagePath, hooksFound);
                break;
            case CPUArchitecture::X64:
                CheckForHooks<CPUArchitecture::X64>(memDs, mCached64, image.ImagePath, hooksFound);
                break;
            }

            if (!hooksFound.empty())
                callbacks->OnHooksFound(hooksFound, image.ImagePath.c_str());
        }
    }  
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
    callbacks = scanCallbacks;

    if (!MemoryHelper<arch>::EnableDebugPrivilege())
        GetDefaultLogger()->Log(ILogger::Info, L"Unable to enable SeDebugPrivilege, functionality is limited\n");

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
            callbacks = scanCallbacks;

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
                    GetDefaultLoggerForThread()->Log(ILogger::Error, L"Unhandled exception: %S\n", e.what());
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

MemoryScanner& MemoryScanner::GetInstance()
{
    static MemoryScanner scanner;
    return scanner;
}
