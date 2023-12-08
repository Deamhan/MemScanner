#pragma once

#include <cinttypes>
#include <memory>
#include <string>

#include "memhelper.hpp"
#include "pe.hpp"

class MemoryScanner
{
public:

	enum class Sensitivity
	{
		Off,
		Low,
		Medium,
		High
	};

	class ICallbacks
	{
	public:
		virtual void OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT& continiousRegions,
			const std::vector<uint64_t>& threadEntryPoints) = 0;

		virtual void OnHooksFound(const std::vector<HookDescription>& hooks, const wchar_t* imageName) = 0;

		virtual void OnProcessScanBegin(uint32_t processId, LARGE_INTEGER creationTime, HANDLE hProcess, const std::wstring& processName) = 0;
		virtual void OnProcessScanEnd() = 0;

		virtual ~ICallbacks() = default;

		// config requests
		virtual Sensitivity GetMemoryAnalysisSettings(std::vector<uint64_t>& addressesToCheck, bool& scanImageForHooks) = 0;
		virtual Sensitivity GetThreadAnalysisSettings() = 0;
		virtual Sensitivity GetHookAnalysisSettings() = 0;
		virtual bool SkipProcess(uint32_t processId, LARGE_INTEGER creationTime, const std::wstring& processName) = 0;

	};

	class DefaultCallbacks : public ICallbacks
	{
	public:
		void OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT& continiousRegions,
			const std::vector<uint64_t>& threadEntryPoints) override;

		void OnHooksFound(const std::vector<HookDescription>& hooks, const wchar_t* imageName) override;

		void OnProcessScanBegin(uint32_t processId, LARGE_INTEGER creationTime, HANDLE hProcess, const std::wstring& processName) override;
		void OnProcessScanEnd() override;

		void SetDumpsRoot(const wchar_t* dumpsRoot);

		DefaultCallbacks(const DefaultCallbacks&) = delete;
		DefaultCallbacks(DefaultCallbacks&&) = delete;
		DefaultCallbacks& operator = (const DefaultCallbacks&) = delete;
		DefaultCallbacks& operator = (DefaultCallbacks&&) = delete;

		DefaultCallbacks(uint32_t pidToScan = 0, Sensitivity memoryScanSensitivity = Sensitivity::Low,
			Sensitivity hookScanSensitivity = Sensitivity::Low, Sensitivity threadsScanSensitivity = Sensitivity::Low,
			uint64_t addressToScan = 0) 
			: mCurrentPid(0), mProcess(nullptr), mPidToScan(pidToScan), mMemoryScanSensitivity(memoryScanSensitivity),
			mHookScanSensitivity(hookScanSensitivity), mThreadScanSensitivity(threadsScanSensitivity), mAddressToScan(addressToScan)
		{
			mProcessCreationTime.QuadPart = 0;
		}

		Sensitivity GetMemoryAnalysisSettings(std::vector<uint64_t>& addressesToScan, bool& scanImageForHooks) override;
		Sensitivity GetThreadAnalysisSettings() override { return mThreadScanSensitivity; }
		Sensitivity GetHookAnalysisSettings() override { return mHookScanSensitivity; }
		bool SkipProcess(uint32_t processId, LARGE_INTEGER, const std::wstring&) override { return !(mPidToScan == 0 || mPidToScan == processId); }

	protected:
		LARGE_INTEGER mProcessCreationTime;
		unsigned mCurrentPid;

		std::wstring mDumpRoot;
		std::wstring mProcessName;
		HANDLE mProcess;

		uint32_t mPidToScan;
		Sensitivity mMemoryScanSensitivity;
		Sensitivity mHookScanSensitivity;
		Sensitivity mThreadScanSensitivity;

		uint64_t mAddressToScan;

		virtual void RegisterNewDump(const MemoryHelperBase::MemInfoT64& /*info*/, const std::wstring& /*dumpPath*/) {}
	};

	void Scan();

	MemoryScanner(std::shared_ptr<ICallbacks> callbacks = std::make_shared<DefaultCallbacks>()) noexcept :
		mCallbacks(std::move(callbacks)){}
	
	const std::shared_ptr<ICallbacks>& GetCallbacks() const noexcept { return mCallbacks; }

	MemoryScanner(const MemoryScanner&) = delete;
	MemoryScanner(MemoryScanner&&) = delete;
	MemoryScanner& operator = (const MemoryScanner&) = delete;
	MemoryScanner& operator = (MemoryScanner&&) = delete;

private:
	std::shared_ptr<ICallbacks> mCallbacks;

	std::map<std::wstring, PE<false, CPUArchitecture::X86>> mCached32;
	std::map<std::wstring, PE<false, CPUArchitecture::X64>> mCached64;

	template <CPUArchitecture arch>
	void ScanMemoryImpl();

	template <CPUArchitecture arch, typename SPI = SystemDefinitions::SYSTEM_PROCESS_INFORMATION_T<PTR_T<arch>>>
	void ScanProcessMemory(SPI* procInfo, const Wow64Helper<arch>& api);
};
