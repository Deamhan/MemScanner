#include <vector>

#include "callbacks.hpp"
#include "file.hpp"
#include "log.hpp"
#include "memdatasource.hpp"
#include "memhelper.hpp"
#include "pe.hpp"
#include "scanner.hpp"

MemoryHelperBase::FlatMemoryMapT detectedMap;

class TestCallbacks : public DefaultCallbacks
{
public:
	TestCallbacks(uint64_t address, uint32_t size) :
		DefaultCallbacks({ GetCurrentProcessId(), address, size, true, OperationType::Write },
			{ MemoryScanner::Sensitivity::Low, MemoryScanner::Sensitivity::Low, MemoryScanner::Sensitivity::Off }),
		mPrivateCodeModification(false), mImageHeadersModification(false)
	{}

	void OnPrivateCodeModification(const wchar_t* /*imageName*/, uint64_t /*imageBase*/ , uint32_t /*rva*/, uint32_t /*size*/) override
	{
		mPrivateCodeModification = true;
	}

	void OnImageHeadersModification(const wchar_t* /*imageName*/, uint64_t /*imageBase*/, uint32_t /*rva*/, uint32_t /*size*/) override
	{
		mImageHeadersModification = true;
	}

	bool mPrivateCodeModification;
	bool mImageHeadersModification;
};

static bool TestFakeImageModification()
{
	const auto& helper = GetMemoryHelper();
	uint64_t peb = 0, wow64peb = 0;
	if (!helper.GetPebAddress(GetCurrentProcess(), peb, wow64peb) || peb == 0)
		return false;

	auto moduleHandle = GetModuleHandleW(L"kernelbase");
	if (moduleHandle == nullptr)
		return false;

	auto callbacks = std::make_shared<TestCallbacks>((uintptr_t)moduleHandle, 0x10000);
	MemoryScanner::GetInstance().Scan(callbacks);

	return callbacks->mPrivateCodeModification && callbacks->mImageHeadersModification;
}

int main()
{
	return TestFakeImageModification() ? 0 : 1;
}
