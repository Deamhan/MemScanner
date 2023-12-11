#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "callbacks.hpp"
#include "scanner.hpp"

static thread_local uint32_t pid = 0;

class MyCallbacks : public DefaultCallbacks
{
public:
    void OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT&,
        const std::vector<uint64_t>&) override
    {}

    void OnHooksFound(const std::vector<HookDescription>&, const wchar_t*) override
    {}

    void OnProcessScanBegin(uint32_t processId, LARGE_INTEGER ct, HANDLE hProcess, const std::wstring& processName) override
    {
        pid = hProcess != nullptr ? processId : 0;
        Super::OnProcessScanBegin(processId, ct, hProcess, processName);


        std::lock_guard<std::mutex> lg(mLock);
        mScannedPids.emplace(GetCurrentThreadId(), processId);
    }

    MyCallbacks() : DefaultCallbacks() {}

    const std::multimap<uint32_t, uint32_t>& GetScannedPids()
    {
        return mScannedPids;
    }

    void OnProcessScanEnd() override
    {
        Super::OnProcessScanEnd();

        if (pid != 0 && pid != currentScanData.pid)
            throw std::logic_error("Invalid callbacks data");
    }

private:
    typedef DefaultCallbacks Super;
    std::multimap<uint32_t, uint32_t> mScannedPids;
    std::mutex mLock;

};

#define WORKERS_COUNT 2

int main()
{
    auto myCallbacks = std::make_shared<MyCallbacks>();
    MemoryScanner::GetInstance().Scan(myCallbacks, WORKERS_COUNT);

    std::set<uint32_t> tids;
    const auto results = myCallbacks->GetScannedPids();
    for (const auto& result : results)
        tids.insert(result.first);

    printf("%u", (unsigned)tids.size());
    return tids.size() == WORKERS_COUNT ? 0 : 1;
}
