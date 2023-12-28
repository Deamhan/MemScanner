#include "callbacks.hpp"
#include "file.hpp"
#include "log.hpp"
#include "memdatasource.hpp"
#include "pe.hpp"

#include "yara.hpp"

thread_local DefaultCallbacks::CurrentScanStateData DefaultCallbacks::currentScanData;

MemoryScanner::Sensitivity DefaultCallbacks::GetMemoryAnalysisSettings(
    std::vector<AddressInfo>& addressRangesToCheck, bool& scanImageForHooks, bool& scanRangesWithYara)
{
    addressRangesToCheck.clear();
    scanImageForHooks = false;

    if (mAddressToScan != 0)
    {
        AddressInfo info = { mAddressToScan, mSizeOfRange, mForceWritten };
        addressRangesToCheck.push_back(info);
        scanImageForHooks = true;
        scanRangesWithYara = true;
    }

    return mMemoryScanSensitivity;
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

void DefaultCallbacks::OnWritableExecImageFound(const MemoryHelperBase::FlatMemoryMapT& /*continiousRegions*/,
    const std::wstring& imagePath, const MemoryHelperBase::MemInfoT64& wxRegion, bool& scanWithYara)
{
    scanWithYara = true;
    GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\tWX memory region in image %s+0x%llx, 0x%llx\n",
        imagePath.c_str(), (unsigned long long)(wxRegion.BaseAddress - wxRegion.AllocationBase),
        (unsigned long long)wxRegion.RegionSize);
}

void DefaultCallbacks::OnPrivateCodeModification(const wchar_t* imageName, uint64_t /*imageBase*/, uint32_t rva, uint32_t /*size*/)
{
    GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\tPrivate code modification: %s+0x%08x\n",
        imageName, (unsigned)rva);
}

void DefaultCallbacks::OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT& relatedRegions,
    const std::vector<uint64_t>& threadEntryPoints, bool& scanRangesWithYara)
{
    scanRangesWithYara = false;

    GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\tSuspicious memory region:\n");
    for (const auto& region : relatedRegions)
        printMBI<uint64_t>(region, L"\t\t");

    if (!threadEntryPoints.empty())
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\t\tRelated threads:\n");
        for (const auto threadEP : threadEntryPoints)
            GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\t\t\t0x%llx\n", (unsigned long long)threadEP);

        GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\n");
    }

    bool isPeFound = false;
    for (const auto& region : relatedRegions)
    {
        auto peFound = ScanRegionForPeHeaders(currentScanData.process, region);
        if (peFound.first != 0)
        {
            GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\t\tPE (%s) found: 0x%llx\n", CpuArchToString(peFound.second),
                (unsigned long long)peFound.first);
            isPeFound = true;
            scanRangesWithYara = true;
        }
    }

    if (isPeFound)
        GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\n");
    else if (ScanRegionForPeSections(currentScanData.process, relatedRegions))
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\t\tPossible PE found: 0x%llx\n",
            (unsigned long long)relatedRegions.begin()->AllocationBase);

        scanRangesWithYara = true;
    }
    else if (mMemoryScanSensitivity >= MemoryScanner::Sensitivity::Medium)
        scanRangesWithYara = true;

    if (mDumpRoot.empty())
        return;

    std::wstring processDumpDir = mDumpRoot;
    wchar_t buffer[64] = {};
    _snwprintf_s(buffer, _countof(buffer), L"_%u_%llu", (unsigned)currentScanData.pid, (unsigned long long)currentScanData.processCreationTime.QuadPart);
    processDumpDir.append(currentScanData.processName).append(buffer);

    if (!CreateDirectoryW(processDumpDir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Error, L"\tUnable to create directory %s:\n", processDumpDir.c_str());
        return;
    }

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
    GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\tHooks for %s:\n", imageName);
    for (const auto& hook : hooks)
    {
        for (const auto& name : hook.functionDescription->names)
            GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\t\t%S\n", name.c_str());

        GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\t\tOrdinal: %d\n\n", hook.functionDescription->ordinal);
    }
}

void DefaultCallbacks::OnYaraDetection(const std::list<std::string>& detections)
{
    for (const auto& detection : detections)
        GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\tYARA detection: %S\n", detection.c_str());
}

void DefaultCallbacks::OnProcessScanBegin(uint32_t processId, LARGE_INTEGER creationTime, HANDLE hProcess, const std::wstring& processName)
{
    if (hProcess == nullptr)
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Error, L"Process %s [PID = %u, CreateTime = %llu]: unable to open\n", processName.c_str(),
            (unsigned)processId, (unsigned long long)creationTime.QuadPart);
        return;
    }

    GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"Process %s [PID = %u, CreateTime = %llu]\n", processName.c_str(),
        (unsigned)processId, (unsigned long long)creationTime.QuadPart);

    currentScanData.pid = processId;
    currentScanData.processName = processName;
    currentScanData.process = hProcess;
    currentScanData.processCreationTime = creationTime;
}

void DefaultCallbacks::OnProcessScanEnd()
{
    if (currentScanData.process != 0)
        GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"Process [PID = %u]: done\n", currentScanData.pid);
}

const std::list<std::string> predefinedRules{ "\
            rule PeSig { \
              strings: \
                $dosText = \"This program cannot be run in DOS mode\" \
                $PeMagic = { 45 50 00 00 } \
                $TextSec = \".text\" \
                $CodeSec = \".code\" \
              condition: \
                ($dosText and ($TextSec or $CodeSec)) or ($PeMagic and ($TextSec or $CodeSec))\
             }" };

DefaultCallbacks::DefaultCallbacks(uint32_t pidToScan, uint64_t addressToScan, uint64_t sizeOfRangeToScan, bool forceWritten,
    bool externalOperation, MemoryScanner::Sensitivity memoryScanSensitivity, MemoryScanner::Sensitivity hookScanSensitivity,
    MemoryScanner::Sensitivity threadsScanSensitivity, const wchar_t* dumpsRoot)
    : mPidToScan(pidToScan), mMemoryScanSensitivity(memoryScanSensitivity), mHookScanSensitivity(hookScanSensitivity),
    mThreadScanSensitivity(threadsScanSensitivity), mAddressToScan(addressToScan), mSizeOfRange(sizeOfRangeToScan),
    mForceWritten(forceWritten), mExternalOperation(externalOperation)
{
    if (dumpsRoot == nullptr)
        return;

    mDumpRoot = dumpsRoot;
    if (mDumpRoot.empty())
        return;

    if (*mDumpRoot.rbegin() != L'\\')
        mDumpRoot += L'\\';
}
