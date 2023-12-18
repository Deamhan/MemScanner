#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "callbacks.hpp"
#include "log.hpp"
#include "scanner.hpp"

static thread_local uint32_t pid = 0;

class MyCallbacks : public DefaultCallbacks
{
public:
    void OnSuspiciousMemoryRegionFound(const MemoryHelperBase::FlatMemoryMapT&,
        const std::vector<uint64_t>&, MemoryScanner*) override
    {}

    void OnHooksFound(const std::vector<HookDescription>&, const wchar_t*) override
    {}

    void OnProcessScanBegin(uint32_t processId, LARGE_INTEGER, HANDLE, const std::wstring& processName) override
    {
        GetDefaultLoggerForThread()->Log(ILogger::Info, L"scanning %u (%s)\n", processId, processName.c_str());
        std::list<std::string> yaraDetections;
        MemoryScanner::GetInstance().ScanProcessUsingYara(processId, yaraDetections);

        for (const auto& detection : yaraDetections)
            GetDefaultLoggerForThread()->Log(ILogger::Info, L"\tYARA: %S\n", detection.c_str());
    }

    MyCallbacks() : DefaultCallbacks(0, 0, MemoryScanner::Sensitivity::Off, MemoryScanner::Sensitivity::Off,
        MemoryScanner::Sensitivity::Off) {}

private:
    typedef DefaultCallbacks Super;
};

int main()
{
    SetDefaultLogger(&ConsoleLogger::GetInstance());

    auto& scanner = MemoryScanner::GetInstance();
    scanner.SetYaraRules(std::make_shared<YaraScanner::YaraRules>(predefinedRules));
    auto myCallbacks = std::make_shared<MyCallbacks>();

    Timer timer{ L"Memory" };
    scanner.Scan(myCallbacks, 0);

    return 0;
}
