#pragma once

#include <cinttypes>
#include <memory>
#include <mutex>
#include <string>

#include "memhelper.hpp"
#include "pe.hpp"
#include "yara.hpp"

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
			const std::vector<uint64_t>& threadEntryPoints, MemoryScanner* scanner) = 0;

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

	void Scan(std::shared_ptr<ICallbacks> scanCallbacks, uint32_t workersCount = 1);

	MemoryScanner(const MemoryScanner&) = delete;
	MemoryScanner(MemoryScanner&&) = delete;
	MemoryScanner& operator = (const MemoryScanner&) = delete;
	MemoryScanner& operator = (MemoryScanner&&) = delete;

	static MemoryScanner& GetInstance();

	bool ScanUsingYara(HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region, std::list<std::string>& result);
	void SetYaraRules(std::shared_ptr<YaraScanner::YaraRules> rules);
	void SetYaraRules(const std::list<std::string>& rules);
	void SetYaraRules(const wchar_t* rulesDirectory);

	static void ResetYaraScannerForThread() noexcept { tlsYaraScanner.reset(); }

private:
	std::pair<std::map<std::wstring, PE<false, CPUArchitecture::X86>>, std::mutex> mCached32;
	std::pair<std::map<std::wstring, PE<false, CPUArchitecture::X64>>, std::mutex> mCached64;

	MemoryScanner() = default;

	template <CPUArchitecture arch>
	void ScanMemoryImpl(uint32_t workersCount, ICallbacks* scanCallbacks);

	template <CPUArchitecture arch, typename SPI = SystemDefinitions::SYSTEM_PROCESS_INFORMATION_T<PTR_T<arch>>>
	void ScanProcessMemory(SPI* procInfo, const Wow64Helper<arch>& api);

	static thread_local ICallbacks* tlsCallbacks;
	static thread_local std::unique_ptr<YaraScanner> tlsYaraScanner;

	std::shared_ptr<YaraScanner::YaraRules> mYaraRules;
	std::mutex mYaraRulesLock;

	YaraScanner* GetYaraScanner();
};
