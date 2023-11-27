#pragma once

#include <cinttypes>
#include <memory>
#include <string>

#include "memhelper.hpp"
#include "pe.hpp"

class MemoryScanner
{
public:
	class ICallbacks
	{
	public:
		virtual void OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT& continiousRegions,
			const std::vector<uint64_t>& threadEntryPoints) = 0;

		virtual void OnHooksFound(std::vector<std::shared_ptr<ExportedFunctionDescription>>& hooks, const wchar_t* imageName) = 0;

		virtual void OnProcessScanBegin(uint32_t processId, LARGE_INTEGER creationTime, HANDLE hProcess, const std::wstring& processName) = 0;
		virtual void OnProcessScanEnd() = 0;

		virtual ~ICallbacks() = default;
	};

	class DefaultCallbacks : public ICallbacks
	{
	public:
		void OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT& continiousRegions,
			const std::vector<uint64_t>& threadEntryPoints) override;

		void OnHooksFound(std::vector<std::shared_ptr<ExportedFunctionDescription>>& hooks, const wchar_t* imageName) override;

		void OnProcessScanBegin(uint32_t processId, LARGE_INTEGER creationTime, HANDLE hProcess, const std::wstring& processName) override;
		void OnProcessScanEnd() override;

		void SetDumpsRoot(const wchar_t* dumpsRoot);

		DefaultCallbacks(const DefaultCallbacks&) = delete;
		DefaultCallbacks(DefaultCallbacks&&) = delete;
		DefaultCallbacks& operator = (const DefaultCallbacks&) = delete;
		DefaultCallbacks& operator = (DefaultCallbacks&&) = delete;

		DefaultCallbacks() : mCurrentPid(0), mProcess(nullptr)
		{
			mProcessCreationTime.QuadPart = 0;
		}

	protected:
		LARGE_INTEGER mProcessCreationTime;
		unsigned mCurrentPid;

		std::wstring mDumpRoot;
		std::wstring mProcessName;
		HANDLE mProcess;

		virtual void RegisterNewDump(const MemoryHelperBase::MemInfoT64& /*info*/, const std::wstring& /*dumpPath*/) {}
	};

	void Scan(uint32_t pid = 0);

	enum Sensitivity
	{
		Low,
		Medium,
		High
	};

	MemoryScanner(Sensitivity sensitivity, std::shared_ptr<ICallbacks> callbacks = std::make_shared<DefaultCallbacks>()) noexcept :
		mSensitivity(sensitivity), mCallbacks(std::move(callbacks)){}
	
	const std::shared_ptr<ICallbacks>& GetCallbacks() const noexcept { return mCallbacks; }

	Sensitivity GetSensitivity() const noexcept { return mSensitivity; }

	MemoryScanner(const MemoryScanner&) = delete;
	MemoryScanner(MemoryScanner&&) = delete;
	MemoryScanner& operator = (const MemoryScanner&) = delete;
	MemoryScanner& operator = (MemoryScanner&&) = delete;

private:
	Sensitivity mSensitivity;
	std::shared_ptr<ICallbacks> mCallbacks;

	std::map<std::wstring, PE<false, CPUArchitecture::X86>> mCached32;
	std::map<std::wstring, PE<false, CPUArchitecture::X64>> mCached64;

	template <CPUArchitecture arch>
	void ScanMemoryImpl(uint32_t pid);

	template <CPUArchitecture arch, typename SPI = SystemDefinitions::SYSTEM_PROCESS_INFORMATION_T<PTR_T<arch>>>
	void ScanProcessMemory(SPI* procInfo, const Wow64Helper<arch>& api);
};
