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

	bool OnExplicitAddressScan(const MemoryHelperBase::MemInfoT64& regionInfo,
		MemoryHelperBase::MemoryMapConstIteratorT rangeBegin, MemoryHelperBase::MemoryMapConstIteratorT rangeEnd,
		bool isAlignedAllocation) override;

    void OnWritableExecImageFound(const MemoryHelperBase::FlatMemoryMapT& continiousRegions, const std::wstring& imagePath,
		const MemoryHelperBase::MemInfoT64& wxRegion, bool& scanWithYara) override;

    void OnPrivateCodeModification(const wchar_t* imageName, uint64_t imageBase, uint32_t rva, uint32_t size) override;

	void OnHooksFound(const std::vector<HookDescription>& hooks, const wchar_t* imageName) override;
    void OnYaraScan(const MemoryHelperBase::MemInfoT64& region, uint64_t startAddress, uint64_t size, bool imageOverwrite,
		bool externalOperation, bool isAlignedAllocation, const std::set<std::string>* detections) override;

	void OnProcessScanBegin(uint32_t processId, LARGE_INTEGER creationTime, HANDLE hProcess, const std::wstring& processName) override;
	void OnProcessScanEnd() override;

	struct ScanningGeneralSettings
	{
		typedef MemoryScanner::Sensitivity Sensitivity;
		typedef LoggerBase::Level LogLevel;

		Sensitivity memoryScanSensitivity ;
		Sensitivity hookScanSensitivity;
		Sensitivity threadsScanSensitivity;
		LoggerBase::Level defaultLoggingLevel;
		const wchar_t* dumpsRoot;

		ScanningGeneralSettings(Sensitivity _memoryScanSensitivity = Sensitivity::Low,
			Sensitivity _hookScanSensitivity = Sensitivity::Low,
			Sensitivity _threadsScanSensitivity = Sensitivity::Low,
			LogLevel _defaultLoggingLevel = LoggerBase::Debug,
			const wchar_t* _dumpsRoot = nullptr) noexcept :
			memoryScanSensitivity(_memoryScanSensitivity), hookScanSensitivity(_hookScanSensitivity), 
			threadsScanSensitivity(_threadsScanSensitivity), defaultLoggingLevel(_defaultLoggingLevel),
			dumpsRoot(_dumpsRoot)
		{}
	};

	struct ScanningTarget
	{
		uint32_t pidToScan;
		uint64_t addressToScan;
		uint64_t sizeOfRangeToScan;
		bool forceWritten;
		bool externalOperation;
		bool forceCodeStart;

		ScanningTarget(uint32_t _pidToScan = 0, uint64_t _addressToScan = 0, uint64_t _sizeOfRangeToScan = 0,
			bool _forceWritten = false, bool _externalOperation = false, bool _forceCodeStart = false) noexcept :
			pidToScan(_pidToScan), addressToScan(_addressToScan), sizeOfRangeToScan(_sizeOfRangeToScan),
			forceWritten(_forceWritten), externalOperation(_externalOperation), forceCodeStart(_forceCodeStart)
		{}
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

	virtual void RegisterNewDump(const MemoryHelperBase::MemInfoT64& /*region*/, const std::wstring& /*dumpPath*/) {}
	virtual void OnPeFound(uint64_t address, CPUArchitecture arch);

	std::wstring CreateDumpsDirectory();
	std::wstring WriteMemoryDump(const MemoryHelperBase::MemInfoT64& region, const std::wstring& processDumpDir);

	template<class Iter>
	bool IsClrJitLikeMemoryRegion(Iter begin, Iter end, bool isAlignedAllocation);
};

extern const std::list<std::string> predefinedRules;
