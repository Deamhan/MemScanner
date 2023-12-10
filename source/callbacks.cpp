#include "callbacks.hpp"
#include "file.hpp"
#include "log.hpp"
#include "memdatasource.hpp"

#include "yara.hpp"

thread_local DefaultCallbacks::CurrentScanStateData DefaultCallbacks::currentScanData;

MemoryScanner::Sensitivity DefaultCallbacks::GetMemoryAnalysisSettings(
    std::vector<uint64_t>& addressesToScan, bool& scanImageForHooks)
{
    addressesToScan.clear();
    scanImageForHooks = false;

    if (mAddressToScan != 0)
    {
        addressesToScan.push_back(mAddressToScan);
        scanImageForHooks = true;
    }

    return mMemoryScanSensitivity;
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

static bool IsSectionBorder(const uint8_t* buffer, size_t size)
{
    for (size_t i = 0; i < size / 2; ++i)
    {
        if (buffer[i] != 0)
            return false;
    }

    size_t counter = 0;
    for (size_t i = size / 2; i < size; ++i)
    {
        if (buffer[i] != 0)
            ++counter;
    }

    return counter * 4 >= size;
}

static bool ScanRegionForPeSections(HANDLE hProcess, const MemoryHelperBase::FlatMemoryMapT relatedRegions)
{
    if (relatedRegions.empty())
        return false;

    auto last = relatedRegions.rbegin();
    auto begin = relatedRegions.begin()->BaseAddress, end = last->BaseAddress + last->RegionSize;
    auto size = end - begin;

    if (size < 16 * PAGE_SIZE)
        return false;

    ReadOnlyMemoryDataSource ds(hProcess, begin, size, 0);
    uint8_t buffer[64];
    size_t borders = 0;

    for (int offset = PAGE_SIZE - sizeof(buffer) / 2; offset + sizeof(buffer) / 2 <= size; offset += PAGE_SIZE)
    {
        try
        {
            ds.Read(offset, buffer, sizeof(buffer));
            if (IsSectionBorder(buffer, sizeof(buffer)))
                ++borders;
        }
        catch (const DataSourceException&)
        {
        }
    }

    if (borders == 0)
        return false;

    return size / borders > 4 * PAGE_SIZE;
}

void DefaultCallbacks::OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT& relatedRegions,
    const std::vector<uint64_t>& threadEntryPoints)
{
    std::list<std::string> yaraDetections;
    GetDefaultLoggerForThread()->Log(ILogger::Info, L"\tSuspicious memory region:\n");
    for (const auto& region : relatedRegions)
        printMBI<uint64_t>(region, L"\t\t");

    if (!threadEntryPoints.empty())
    {
        GetDefaultLoggerForThread()->Log(ILogger::Info, L"\t\tRelated threads:\n");
        for (const auto threadEP : threadEntryPoints)
            GetDefaultLoggerForThread()->Log(ILogger::Info, L"\t\t\t0x%llx\n", (unsigned long long)threadEP);

        GetDefaultLoggerForThread()->Log(ILogger::Info, L"\n");
    }

    bool isPeFound = false;
    for (const auto& region : relatedRegions)
    {
        auto peFound = ScanRegionForPE(currentScanData.process, region);
        if (peFound.first != 0)
        {
            GetDefaultLoggerForThread()->Log(ILogger::Info, L"\t\tPE (%s) found: 0x%llx\n", CpuArchToString(peFound.second),
                (unsigned long long)peFound.first);
            isPeFound = true;

            ScanUsingYara(mYaraScanner, currentScanData.process, region, yaraDetections);
            for (const auto& detection : yaraDetections)
                GetDefaultLoggerForThread()->Log(ILogger::Info, L"\t\tYARA: %S\n", detection.c_str());
        }
    }

    if (isPeFound)
        GetDefaultLoggerForThread()->Log(ILogger::Info, L"\n");
    else if (ScanRegionForPeSections(currentScanData.process, relatedRegions))
    {
        GetDefaultLoggerForThread()->Log(ILogger::Info, L"\t\tPossible PE found: 0x%llx\n",
            (unsigned long long)relatedRegions.begin()->AllocationBase);

        for (const auto& region : relatedRegions)
        {
            ScanUsingYara(mYaraScanner, currentScanData.process, region, yaraDetections);
            for (const auto& detection : yaraDetections)
                GetDefaultLoggerForThread()->Log(ILogger::Info, L"\t\tYARA: %S\n", detection.c_str());
        }
    }

    if (mDumpRoot.empty())
        return;

    std::wstring processDumpDir = mDumpRoot;
    wchar_t buffer[64] = {};
    _snwprintf_s(buffer, _countof(buffer), L"_%u_%llu", (unsigned)currentScanData.pid, (unsigned long long)currentScanData.processCreationTime.QuadPart);
    processDumpDir.append(currentScanData.processName).append(buffer);

    if (!CreateDirectoryW(processDumpDir.c_str(), nullptr))
        GetDefaultLoggerForThread()->Log(ILogger::Error, L"\tUnable to create directory %s:\n", processDumpDir.c_str());

    for (const auto& region : relatedRegions)
    {
        ReadOnlyMemoryDataSource dsToDump(currentScanData.process, region.BaseAddress, region.RegionSize);
        std::wstring dumpPath = processDumpDir;
        _snwprintf_s(buffer, _countof(buffer), L"\\%llx.bin", (unsigned long long)region.BaseAddress);
        dumpPath.append(buffer);
        File dump(dumpPath.c_str(), File::CreateNew, 0);
        dsToDump.Dump(dump, 0, region.RegionSize, 64 * 1024, true);

        RegisterNewDump(region, dumpPath);
    }
}

void DefaultCallbacks::OnHooksFound(const std::vector<HookDescription>& hooks, const wchar_t* imageName)
{
    GetDefaultLoggerForThread()->Log(ILogger::Info, L"\tHooks for %s:\n", imageName);
    for (const auto& hook : hooks)
    {
        for (const auto& name : hook.functionDescription->names)
            GetDefaultLoggerForThread()->Log(ILogger::Info, L"\t\t%S\n", name.c_str());

        GetDefaultLoggerForThread()->Log(ILogger::Info, L"\t\tOrdinal: %d\n\n", hook.functionDescription->ordinal);
    }
}

void DefaultCallbacks::OnProcessScanBegin(uint32_t processId, LARGE_INTEGER creationTime, HANDLE hProcess, const std::wstring& processName)
{
    if (hProcess == nullptr)
    {
        GetDefaultLoggerForThread()->Log(ILogger::Error, L"Process %s [PID = %u, CreateTime = %llu]: unable to open\n", processName.c_str(),
            (unsigned)processId, (unsigned long long)creationTime.QuadPart);
        return;
    }

    GetDefaultLoggerForThread()->Log(ILogger::Info, L"Process %s [PID = %u, CreateTime = %llu]\n", processName.c_str(),
        (unsigned)processId, (unsigned long long)creationTime.QuadPart);

    currentScanData.pid = processId;
    currentScanData.processName = processName;
    currentScanData.process = hProcess;
}

void DefaultCallbacks::OnProcessScanEnd()
{
    if (currentScanData.process != 0)
        GetDefaultLoggerForThread()->Log(ILogger::Info, L"Process [PID = %u]: done\n", currentScanData.pid);
}

const std::list<std::string> predefinedRiles{ "\
            rule PeSig { \
              strings: \
                $dosText = \"This program cannot be run in DOS mode\" \
                $PeMagic = { 45 50 00 00 } \
                $TextSec = \".text\" \
                $CodeSec = \".code\" \
              condition: \
                ($dosText and ($TextSec or $CodeSec)) or ($PeMagic and ($TextSec or $CodeSec))\
             }" };

DefaultCallbacks::DefaultCallbacks(uint32_t pidToScan, MemoryScanner::Sensitivity memoryScanSensitivity,
    MemoryScanner::Sensitivity hookScanSensitivity, MemoryScanner::Sensitivity threadsScanSensitivity, uint64_t addressToScan, const wchar_t* dumpsRoot)
    : mPidToScan(pidToScan), mMemoryScanSensitivity(memoryScanSensitivity), mHookScanSensitivity(hookScanSensitivity),
    mThreadScanSensitivity(threadsScanSensitivity), mAddressToScan(addressToScan)
{
    if (dumpsRoot == nullptr)
        return;

    mDumpRoot = dumpsRoot;
    if (mDumpRoot.empty())
        return;

    if (*mDumpRoot.rbegin() != L'\\')
        mDumpRoot += L'\\';

    SetYaraRules(mYaraScanner, predefinedRiles);
}

