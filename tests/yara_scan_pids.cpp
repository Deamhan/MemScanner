#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <map>
#include <cstdio>
#include <sstream>
#include <stdexcept>
#include <thread>

#include "callbacks.hpp"
#include "log.hpp"
#include "scanner.hpp"

enum class CmdLineSwitch
{
    Pid,
    Log,
    Rules,
    Threads,
    None
};

template <class T>
static void parse(const wchar_t* s, T& value)
{
    std::wstringstream ss(s);
    value = T();
    if (!(ss >> value))
        throw std::domain_error("");
}

template <class T>
static std::wstring toString(T& value)
{
    std::wstringstream ss;
    ss << value;
    std::wstring result;
    ss >> result;

    return result;
}

class MyCallbacks : public DefaultCallbacks
{
public:
    void OnProcessScanBegin(uint32_t processId, LARGE_INTEGER, HANDLE, const std::wstring& processName) override
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"scanning %u (%s)\n", processId, processName.c_str());
        std::list<std::string> yaraDetections;
        MemoryScanner::GetInstance().ScanProcessUsingYara(processId, yaraDetections);

        for (const auto& detection : yaraDetections)
            GetDefaultLoggerForThread()->Log(LoggerBase::Info, L"\tYARA: %S\n", detection.c_str());
    }

    MyCallbacks(uint32_t pid = 0) : DefaultCallbacks({ pid }, { MemoryScanner::Sensitivity::Off, MemoryScanner::Sensitivity::Off,
        MemoryScanner::Sensitivity::Off }) {}

private:
    typedef DefaultCallbacks Super;
};

static void PrintHelp()
{
    wprintf(L"Help: yara_scan_mem.exe [-pid ID] [-log path] [-threads N] [-rules rulesDir]\n"
        "\tdefault: all processes scan, predefined rules, single thread\n");
}

int wmain(int argc, const wchar_t** argv)
{
    CmdLineSwitch state = CmdLineSwitch::None;
    std::wstring logPath, rulesDir;
    uint32_t pid = 0, threadsCount = 1;
    for (int i = 1; i < argc; ++i)
    {
        try
        {
            if (argv[i][0] == L'-' || argv[i][0] == L'/')
            {
                if (wcscmp(argv[i] + 1, L"pid") == 0)
                    state = CmdLineSwitch::Pid;
                else if (wcscmp(argv[i] + 1, L"log") == 0)
                    state = CmdLineSwitch::Log;
                else if (wcscmp(argv[i] + 1, L"rules") == 0)
                    state = CmdLineSwitch::Rules;
                else if (wcscmp(argv[i] + 1, L"threads") == 0)
                    state = CmdLineSwitch::Threads;
                else if (wcscmp(argv[i] + 1, L"help") == 0)
                {
                    PrintHelp();
                    return 0;
                }
                else
                    throw std::invalid_argument("");
            }
            else
            {
                switch (state)
                {
                case CmdLineSwitch::Pid:
                    parse(argv[i], pid);
                    break;
                case CmdLineSwitch::Threads:
                    parse(argv[i], threadsCount);
                    break;
                case CmdLineSwitch::Log:
                    logPath = argv[i];
                    break;
                case CmdLineSwitch::Rules:
                    rulesDir = argv[i];
                    break;
                default:
                    throw std::domain_error("");
                }

                state = CmdLineSwitch::None;
            }
        }
        catch (const std::invalid_argument&)
        {
            wprintf(L"Unknown switch: %s\n\n", argv[i] + 1);

            PrintHelp();
            return 1;
        }
        catch (const std::domain_error&)
        {
            wprintf(L"Invalid argument: %s\n\n", argv[i]);

            PrintHelp();
            return 1;
        }
    }

    wprintf(L"Settings:\n\tpid = %s\n\tlog = %s\n\tthreads = %u\n\trules directory = %s\n\n",
        pid == 0 ? L"all" : toString(pid).c_str(),
        logPath.empty() ? L"console" : logPath.c_str(),
        threadsCount == 0 ? std::thread::hardware_concurrency() : threadsCount,
        rulesDir.empty() ? L"none (prefedined set)" : rulesDir.c_str());

    try
    {
        LoggerBase* logger = logPath.empty() ? (LoggerBase*)&ConsoleLogger::GetInstance() : (LoggerBase*)&FileLogger::GetInstance(logPath.c_str());
        SetDefaultLogger(logger);

        auto& scanner = MemoryScanner::GetInstance();
        if (rulesDir.empty())
            scanner.SetYaraRules(std::make_shared<YaraScanner::YaraRules>(predefinedRules));
        else
            scanner.SetYaraRules(std::make_shared<YaraScanner::YaraRules>(rulesDir.c_str()));

        auto myCallbacks = std::make_shared<MyCallbacks>(pid);

        Timer timer{ L"Memory" };
        scanner.Scan(myCallbacks, threadsCount);
    }
    catch (const std::exception& e)
    {
        wprintf(L"Error: %S\n", e.what());
        return 2;
    }

    return 0;
}
