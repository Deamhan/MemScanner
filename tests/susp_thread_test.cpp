#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "callbacks.hpp"
#include "scanner.hpp"

static void FreeVirtualMemory(void* p)
{
    VirtualFree(p, 0, MEM_RELEASE);
}

static void TestThreadFunc(HANDLE hEvent)
{
    SetEvent(hEvent);
    while (true)
        Sleep(1000);
}

class MyCallbacks : public DefaultCallbacks
{
public:
    void OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT& continiousRegions,
        const std::vector<uint64_t>& threadEntryPoints, bool& scanWithYara) override
    {
        Super::OnSuspiciousMemoryRegionFound(continiousRegions, threadEntryPoints, scanWithYara);

        std::lock_guard<std::mutex> guard(lock);
        mFoundThreadEPs.insert(threadEntryPoints.begin(), threadEntryPoints.end());
    }

    const auto& GetFoundEPs() const noexcept
    {
        return mFoundThreadEPs;
    }

    void RegisterNewDump(const MemoryHelperBase::MemInfoT64& info, const std::wstring& dumpPath) override
    {
        std::lock_guard<std::mutex> guard(lock);
        mDumped.emplace(info.BaseAddress, dumpPath);
    }

    const std::map<uint64_t, std::wstring>& GetDumped() const noexcept { return mDumped; }

    MyCallbacks() : DefaultCallbacks(GetCurrentProcessId(), 0, 0, false, MemoryScanner::Sensitivity::Low,
        MemoryScanner::Sensitivity::Low, MemoryScanner::Sensitivity::Low, L".") {}

private:
    typedef DefaultCallbacks Super;
    std::set<uint64_t> mFoundThreadEPs;
    std::map<uint64_t, std::wstring> mDumped;

    std::mutex lock;

    MyCallbacks(const MyCallbacks&) = default;
    MyCallbacks& operator = (const MyCallbacks&) = default;
};

int main()
{
#if _M_AMD64
    const uint8_t code[] = { 0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0xFF, 0xE0 };
    const size_t offset = 2;
#else
    const uint8_t code[] = { 0xB8, 0x78, 0x56, 0x34, 0x12, 0xFF, 0xE0 };
    const size_t offset = 1;
#endif // _M_AMD64
    auto pExec = (uint8_t*)VirtualAlloc(nullptr, sizeof(code), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pExec == nullptr)
    {
        wprintf(L"!>> Unable to allocate memory <<!\n");
        return 1;
    }

    std::unique_ptr<void, void (*)(void*)> vGuard(pExec, FreeVirtualMemory);
    wprintf(L"### Thread address = 0x%016llx ###\n\n", (unsigned long long)pExec);
    memcpy(pExec, code, sizeof(code));
    *(uintptr_t*)(pExec + offset) = (uintptr_t)TestThreadFunc;
    DWORD oldProt = 0;
    VirtualProtect(pExec, sizeof(code), PAGE_EXECUTE_READ, &oldProt);

    HANDLE hEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    std::unique_ptr<HANDLE, void(*)(HANDLE*)> eventGuard(&hEvent, MemoryHelperBase::CloseHandleByPtr);
    HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)pExec, hEvent, 0, nullptr);
    std::unique_ptr<HANDLE, void(*)(HANDLE*)> threadGuard(&hThread, MemoryHelperBase::CloseHandleByPtr);
    WaitForSingleObject(hEvent, INFINITE);

    auto myCallbacks = std::make_shared<MyCallbacks>();
    MemoryScanner::GetInstance().Scan(myCallbacks, 1);

    const auto& found = myCallbacks->GetFoundEPs();
    if (found.find((uintptr_t)pExec) == found.end())
    {
        wprintf(L"!>> Unable to find the threat <<!\n");
        return 1;
    }

    const auto& dumped = myCallbacks->GetDumped();
    auto dumpFound = dumped.find((uintptr_t)pExec);
    if (dumpFound == dumped.end())
    {
        wprintf(L"!>> Unable to find the threat dump entry <<!\n");
        return 2;
    }

    if (GetFileAttributesW(dumpFound->second.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        wprintf(L"!>> Unable to find the threat dump file<<!\n");
        return 3;
    }

    return 0;
}
