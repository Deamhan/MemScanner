#pragma once

#include <atomic>

#include "log.hpp"
#include "scanner.hpp"
#include "yara.hpp"

class DefaultCallbacks : public MemoryScanner::ICallbacks
{
public:
	void OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT& continiousRegions,
		const std::vector<uint64_t>& threadEntryPoints, bool& scanWithYara) override;

    void OnWritableExecImageFound(const MemoryHelperBase::FlatMemoryMapT& continiousRegions, const std::wstring& imagePath,
		const MemoryHelperBase::MemInfoT64& wxRegion, bool& scanWithYara) override;

    void OnPrivateCodeModification(const wchar_t* imageName, uint64_t imageBase, uint32_t rva, uint32_t size) override;

	void OnHooksFound(const std::vector<HookDescription>& hooks, const wchar_t* imageName) override;
	void OnYaraDetection(const std::list<std::string>& detections) override;

	void OnProcessScanBegin(uint32_t processId, LARGE_INTEGER creationTime, HANDLE hProcess, const std::wstring& processName) override;
	void OnProcessScanEnd() override;

	struct ScanningGeneralSettings
	{
		MemoryScanner::Sensitivity memoryScanSensitivity = MemoryScanner::Sensitivity::Low;
		MemoryScanner::Sensitivity hookScanSensitivity = MemoryScanner::Sensitivity::Low;
		MemoryScanner::Sensitivity threadsScanSensitivity = MemoryScanner::Sensitivity::Low;
		LoggerBase::Level defaultLoggingLevel = LoggerBase::Debug;
		const wchar_t* dumpsRoot = nullptr;
	};

	struct ScanningTarget
	{
		uint32_t pidToScan = 0;
		uint64_t addressToScan = 0;
		uint64_t sizeOfRangeToScan = 0;
		bool forceWritten = false;
		bool externalOperation = false;
		bool forceCodeStart = false;
	};

	DefaultCallbacks(const ScanningTarget& scannerTarget, const ScanningGeneralSettings& scannerSettings);

	MemoryScanner::Sensitivity GetMemoryAnalysisSettings(std::vector<AddressInfo>& addressRangesToCheck,
		bool& scanImageForHooks, bool& scanRangesWithYara) override;
	MemoryScanner::Sensitivity GetThreadAnalysisSettings() override { return mThreadScanSensitivity; }
	MemoryScanner::Sensitivity GetHookAnalysisSettings() override { return mHookScanSensitivity; }
	bool SkipProcess(uint32_t processId, LARGE_INTEGER, const std::wstring&) override { return !(mPidToScan == 0 || mPidToScan == processId); }

	struct CurrentScanStateData
	{
		LARGE_INTEGER processCreationTime;
		unsigned pid;
		std::wstring processName;
		HANDLE process;
	};

	DefaultCallbacks(const DefaultCallbacks&) = delete;
	DefaultCallbacks(DefaultCallbacks&&) = delete;
	DefaultCallbacks& operator = (const DefaultCallbacks&) = delete;
	DefaultCallbacks& operator = (DefaultCallbacks&&) = delete;

protected:
	static thread_local CurrentScanStateData currentScanData;

	MemoryScanner::Sensitivity mMemoryScanSensitivity;
	MemoryScanner::Sensitivity mHookScanSensitivity;
	MemoryScanner::Sensitivity mThreadScanSensitivity;
	std::wstring mDumpRoot;
	LoggerBase::Level mDefaultLoggingLevel;

	uint32_t mPidToScan;
	uint64_t mAddressToScan;
	uint64_t mSizeOfRange;
	bool mForceWritten;
	bool mExternalOperation;
	bool mForceCodeStart;

	static std::atomic<unsigned> mDumpCounter;

	virtual void RegisterNewDump(const MemoryHelperBase::MemInfoT64& /*info*/, const std::wstring& /*dumpPath*/) {}
};

extern const std::list<std::string> predefinedRules;
