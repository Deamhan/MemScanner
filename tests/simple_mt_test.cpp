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

class MyCallbacks : public DefaultCallbacks
{
public:
    void OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT&,
        const std::vector<uint64_t>&) override
    {}

    void OnHooksFound(const std::vector<HookDescription>&, const wchar_t*) override
    {}

    void OnProcessScanBegin(uint32_t processId, LARGE_INTEGER, HANDLE, const std::wstring&) override
    {
        std::lock_guard<std::mutex> lg(mLock);
        mScannedPids.emplace(GetCurrentThreadId(), processId);
    }

    MyCallbacks() : DefaultCallbacks(0, MemoryScanner::Sensitivity::Low,
        MemoryScanner::Sensitivity::Low, MemoryScanner::Sensitivity::Low, 0) {}

    const std::multimap<uint32_t, uint32_t>& GetScannedPids()
    {
        return mScannedPids;
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
