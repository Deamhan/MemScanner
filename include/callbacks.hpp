#pragma once

#include "scanner.hpp"

#include "yara.hpp"

class DefaultCallbacks : public MemoryScanner::ICallbacks
{
public:
	void OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT& continiousRegions,
		const std::vector<uint64_t>& threadEntryPoints, MemoryScanner* scanner) override;

	void OnHooksFound(const std::vector<HookDescription>& hooks, const wchar_t* imageName) override;

	void OnProcessScanBegin(uint32_t processId, LARGE_INTEGER creationTime, HANDLE hProcess, const std::wstring& processName) override;
	void OnProcessScanEnd() override;

	DefaultCallbacks(uint32_t pidToScan = 0, uint64_t addressToScan = 0, MemoryScanner::Sensitivity memoryScanSensitivity = MemoryScanner::Sensitivity::Low,
		MemoryScanner::Sensitivity hookScanSensitivity = MemoryScanner::Sensitivity::Low, 
		MemoryScanner::Sensitivity threadsScanSensitivity = MemoryScanner::Sensitivity::Low,
		const wchar_t* dumpsRoot = nullptr);

	MemoryScanner::Sensitivity GetMemoryAnalysisSettings(std::vector<uint64_t>& addressesToScan, bool& scanImageForHooks) override;
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

	uint32_t mPidToScan;
	MemoryScanner::Sensitivity mMemoryScanSensitivity;
	MemoryScanner::Sensitivity mHookScanSensitivity;
	MemoryScanner::Sensitivity mThreadScanSensitivity;
	std::wstring mDumpRoot;

	uint64_t mAddressToScan;

	virtual void RegisterNewDump(const MemoryHelperBase::MemInfoT64& /*info*/, const std::wstring& /*dumpPath*/) {}

	void ScanUsingYara(const MemoryHelperBase::MemInfoT64& region, MemoryScanner* scanner);
};

extern const std::list<std::string> predefinedRules;
