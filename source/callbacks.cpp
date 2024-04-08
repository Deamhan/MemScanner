#include "stdafx.h"

#include "../include/callbacks.hpp"

#include <algorithm>
#include <cstdio>
#include <sstream>

#include "../include/file.hpp"
#include "../include/log.hpp"
#include "../include/memdatasource.hpp"
#include "../include/operations.hpp"
#include "../include/pe.hpp"
#include "../include/yara.hpp"

thread_local DefaultCallbacks::CurrentScanStateData DefaultCallbacks::currentScanData;
std::atomic<unsigned> DefaultCallbacks::mDumpCounter = 0;

MemoryScanner::Sensitivity DefaultCallbacks::GetMemoryAnalysisSettings(
    std::vector<AddressInfo>& addressRangesToCheck, bool& scanImageForHooks, bool& scanRangesWithYara)
{
    addressRangesToCheck.clear();
    scanImageForHooks = false;

    if (mAddressToScan != 0)
    {
        AddressInfo info = { mAddressToScan, mSizeOfRange, mExternalOperation, mOperation };
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
    GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\tWX memory region in image %s+0x%llx, 0x%llx" LOG_ENDLINE_STR,
        imagePath.c_str(), (unsigned long long)(wxRegion.BaseAddress - wxRegion.AllocationBase),
        (unsigned long long)wxRegion.RegionSize);
}

void DefaultCallbacks::OnPrivateCodeModification(const wchar_t* imageName, uint64_t /*imageBase*/, uint32_t rva, uint32_t /*size*/)
{
    GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\tPrivate code modification: %s+0x%08x" LOG_ENDLINE_STR,
        imageName, (unsigned)rva);
}

void DefaultCallbacks::OnImageHeadersModification(const wchar_t* imageName, uint64_t /*imageBase*/, uint32_t rva, uint32_t /*size*/)
{
    GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\tImage headers modification: %s+0x%08x" LOG_ENDLINE_STR,
        imageName, (unsigned)rva);
}

void DefaultCallbacks::OnHiddenImage(const wchar_t* imageName, uint64_t imageBase)
{
    GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\tHidden image found: %s (0x%llx)" LOG_ENDLINE_STR,
        imageName, (unsigned long long)imageBase);
}

void DefaultCallbacks::OnPeFound(uint64_t address, CPUArchitecture arch)
{
    GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\tPE (%s) found: 0x%llx" LOG_ENDLINE_STR, CpuArchToString(arch),
        (unsigned long long)address);
}

void DefaultCallbacks::OnExternalHeapModification(const AddressInfo& info, const MemoryHelperBase::MemInfoT64& regionInfo)
{
    GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\tExternal heap modification: 0x%llx (%S, %s)" LOG_ENDLINE_STR, 
        (unsigned long long)info.address, OperationTypeToText(info.operation), ProtToStr(regionInfo.Protect).c_str());
}

std::wstring DefaultCallbacks::CreateDumpsDirectory()
{
    if (mDumpRoot.empty())
        return std::wstring{};

    std::wstring processDumpDir = mDumpRoot;
    wchar_t buffer[64] = {};
    _snwprintf_s(buffer, _countof(buffer), L"_%u_%llu", (unsigned)currentScanData.pid, (unsigned long long)currentScanData.processCreationTime.QuadPart);
    processDumpDir.append(currentScanData.processName).append(buffer);

    if (!CreateDirectoryW(processDumpDir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Error, L"\tUnable to create directory %s" LOG_ENDLINE_STR, processDumpDir.c_str());
        return std::wstring{};
    }

    return processDumpDir;
}

std::wstring DefaultCallbacks::WriteMemoryDump(const MemoryHelperBase::MemInfoT64& region, const std::wstring& processDumpDir)
{
    if (!MemoryHelperBase::IsReadableRegion(region))
        return std::wstring{};

    wchar_t buffer[64] = {};
    ReadOnlyMemoryDataSource dsToDump(currentScanData.process, region.BaseAddress, region.RegionSize);
    std::wstring dumpPath = processDumpDir;
    _snwprintf_s(buffer, _countof(buffer), L"\\%llx_%u.bin", (unsigned long long)region.BaseAddress,
        mDumpCounter.fetch_add(1, std::memory_order_relaxed));
    dumpPath.append(buffer);
    File dump(dumpPath.c_str(), File::CreateNew, 0);
    dsToDump.Dump(dump, 0, region.RegionSize, 64 * 1024, true);

    RegisterNewDump(region, dumpPath);
    return dumpPath;
}

static const MemoryHelperBase::MemInfoT64& GetRegionByIteratorRef(MemoryHelperBase::MemoryMapConstIteratorT::reference ref)
{
    return ref.second;
}

static const MemoryHelperBase::MemInfoT64& GetRegionByIteratorRef(MemoryHelperBase::FlatMemoryMapConstIteratorT::reference ref)
{
    return ref;
}


/*
 * Heap segments are aligned and have at least one reserved guard page at the end
 */
template<class Iter>
bool DefaultCallbacks::IsHeapLikeMemoryRegion(Iter begin, Iter end, bool isAlignedAllocation)
{
    if (begin == end)
        return false;

    if (!isAlignedAllocation)
        return false;

    // FIXME: test for trailing guard page could be more accurate
    return std::any_of(begin, end, [](const auto& item)
        {
            const auto& region = GetRegionByIteratorRef(item);
            return region.State == MEM_RESERVE;
        });
}

bool DefaultCallbacks::OnExplicitAddressScan(const MemoryHelperBase::MemInfoT64& regionInfo,
    MemoryHelperBase::MemoryMapConstIteratorT rangeBegin, MemoryHelperBase::MemoryMapConstIteratorT rangeEnd,
    bool isAlignedAllocation, const AddressInfo& addrInfo)
{
    bool isHeapLike = IsHeapLikeMemoryRegion(rangeBegin, rangeEnd, isAlignedAllocation);

    // external modification of heap looks as unusual operation
    if (addrInfo.externalOperation && isHeapLike)
    {
        OnExternalHeapModification(addrInfo, regionInfo);
        return true;
    }

    if (mMemoryScanSensitivity > MemoryScanner::Sensitivity::Low)
        return true;

    return !isHeapLike;
}

void DefaultCallbacks::OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT& relatedRegions,
    const std::vector<uint64_t>& codeEntryPoints, bool& scanRangesWithYara)
{
    scanRangesWithYara = false;

    if (mMemoryScanSensitivity == MemoryScanner::Sensitivity::Low 
        && IsHeapLikeMemoryRegion(relatedRegions.cbegin(), relatedRegions.cend(), MemoryHelperBase::IsAlignedAllocation(relatedRegions)))
        return;

    GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"\tSuspicious memory region:" LOG_ENDLINE_STR);
    for (const auto& region : relatedRegions)
        printMBI<uint64_t>(region, mDefaultLoggingLevel, L"\t\t");

    GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"\t\tAligned: %s" LOG_ENDLINE_STR, 
        MemoryHelperBase::IsAlignedAllocation(relatedRegions) ? L"yes" : L"no");

    if (!codeEntryPoints.empty())
    {
        GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"\t\tRelated threads:" LOG_ENDLINE_STR);
        for (const auto threadEP : codeEntryPoints)
            GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"\t\t\t0x%llx" LOG_ENDLINE_STR, (unsigned long long)threadEP);

        GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"" LOG_ENDLINE_STR);
        scanRangesWithYara = true;
    }

    bool isPeFound = false;
    for (const auto& region : relatedRegions)
    {
        if (!MemoryHelperBase::IsReadableRegion(region))
            continue;

        auto peFound = ScanRegionForPeHeaders(currentScanData.process, region);
        if (peFound.first != 0)
        {
            OnPeFound(peFound.first, peFound.second);
            isPeFound = true;
            scanRangesWithYara = true;
        }
    }

    if (isPeFound)
        GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"" LOG_ENDLINE_STR);
    else if (ScanRegionForPeSections(currentScanData.process, relatedRegions))
    {
        GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"\t\tPossible PE found: 0x%llx" LOG_ENDLINE_STR,
            (unsigned long long)relatedRegions.begin()->AllocationBase);

        scanRangesWithYara = true;
    }
    else if (mMemoryScanSensitivity >= MemoryScanner::Sensitivity::Medium)
        scanRangesWithYara = true;
}

void DefaultCallbacks::OnHooksFound(const std::vector<HookDescription>& hooks, const wchar_t* imageName)
{
    GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"\tHooks for %s:" LOG_ENDLINE_STR, imageName);
    for (const auto& hook : hooks)
    {
        for (const auto& name : hook.functionDescription->names)
            GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"\t\t%S" LOG_ENDLINE_STR, name.c_str());

        GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"\t\tOrdinal: %d" LOG_ENDLINE_STR, hook.functionDescription->ordinal);
        GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"" LOG_ENDLINE_STR);
    }
}

static void WriteDumpMetadata(const MemoryHelperBase::MemInfoT64& region, uint64_t startAddress, uint64_t size, bool externalOperation,
    OperationType operation, bool isAlignedAllocation, const std::set<std::string>* detections,
    const std::wstring& dumpPath)
{
    FILE* metadata = nullptr;
    _wfopen_s(&metadata, (dumpPath + L".json").c_str(), L"wb");
    if (metadata == nullptr)
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Error, L"Unable to write metadata to %s" LOG_ENDLINE_STR, dumpPath.c_str());
        return;
    }

    std::unique_ptr<FILE, int(*)(FILE*)> fileGuard(metadata, fclose);

    std::wstringstream result;
    result << L"{\n    \"Info\":\n";
    storeMBI(region, result, L"    ");
    result << L",\n" << std::boolalpha
        << L"    \"Operation\" : " << OperationTypeToText(operation) << L",\n"
        << L"    \"ExternalOperation\" : " << externalOperation << L",\n"
        << L"    \"AlignedAllocation\" : " << isAlignedAllocation << L",\n\n"
        << L"    \"StartAddress\" : \"" << startAddress << L"\",\n"
        << L"    \"Size\" : \"" << size;
    
    if (detections)
    {
        result << L"\",\n\n    \"Detections\" : [";
        for (const auto& detection : *detections)
        {
            std::wstring wDetection{ detection.begin(), detection.end() };
            result << L'\"' << wDetection << L"\", ";
        }

        if (!detections->empty())
            result.seekp(-2, result.cur); // remove last ", " if present

        result << L"]\n}\n";
    }
    else
        result << L"\"\n}\n";

    auto wcharStr = result.str();
    std::string bufferToWrite{ wcharStr.begin(), wcharStr.end() }; // convert unicode to ascii by simple truncation 
    _fwrite_nolock(bufferToWrite.data(), sizeof(bufferToWrite[0]), bufferToWrite.length(), metadata);
}

void DefaultCallbacks::OnYaraScan(const MemoryHelperBase::MemInfoT64& region, uint64_t startAddress, uint64_t size, bool externalOperation, 
    OperationType operation, bool isAlignedAllocation, const std::set<std::string>* detections)
{
    if (detections)
    {
        for (const auto& detection : *detections)
            GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"\tYARA detection: %S" LOG_ENDLINE_STR, detection.c_str());
    }
    
    std::wstring processDumpDir = CreateDumpsDirectory();
    if (processDumpDir.empty())
        return;

    auto dumpFilePath = WriteMemoryDump(region, processDumpDir);
    if (!dumpFilePath.empty())
        WriteDumpMetadata(region, startAddress, size, externalOperation, operation, isAlignedAllocation, detections, dumpFilePath);
}

void DefaultCallbacks::OnProcessScanBegin(uint32_t processId, LARGE_INTEGER creationTime, HANDLE hProcess, const std::wstring& processName)
{
    if (hProcess == nullptr)
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Error, L"Process %s [PID = %u, CreateTime = %llu]: unable to open" LOG_ENDLINE_STR, processName.c_str(),
            (unsigned)processId, (unsigned long long)creationTime.QuadPart);
        return;
    }

    GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"Process %s [PID = %u, CreateTime = %llu]" LOG_ENDLINE_STR, processName.c_str(),
        (unsigned)processId, (unsigned long long)creationTime.QuadPart);

    currentScanData.pid = processId;
    currentScanData.processName = processName;
    currentScanData.process = hProcess;
    currentScanData.processCreationTime = creationTime;
}

void DefaultCallbacks::OnProcessScanEnd()
{
    if (currentScanData.process != nullptr)
        GetDefaultLoggerForThread()->Log(mDefaultLoggingLevel, L"Process [PID = %u]: done" LOG_ENDLINE_STR, currentScanData.pid);
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

DefaultCallbacks::DefaultCallbacks(const ScanningTarget& scannerTarget, const ScanningGeneralSettings& scannerSettings) : 
    mMemoryScanSensitivity(scannerSettings.memoryScanSensitivity),
    mHookScanSensitivity(scannerSettings.hookScanSensitivity),
    mThreadScanSensitivity(scannerSettings.threadsScanSensitivity),
    mDefaultLoggingLevel(scannerSettings.defaultLoggingLevel),
    mPidToScan(scannerTarget.pidToScan), mAddressToScan(scannerTarget.addressToScan),
    mSizeOfRange(scannerTarget.sizeOfRangeToScan), mOperation(scannerTarget.operationType),
    mExternalOperation(scannerTarget.externalOperation)
{
    if (scannerSettings.dumpsRoot == nullptr)
        return;

    mDumpRoot = scannerSettings.dumpsRoot;
    if (mDumpRoot.empty())
        return;

    if (*mDumpRoot.rbegin() != L'\\')
        mDumpRoot += L'\\';
}
