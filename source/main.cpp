#include <Windows.h>

#include <cstdio>
#include <sstream>
#include <stdexcept>
#include <thread>

#include "callbacks.hpp"
#include "log.hpp"
#include "scanner.hpp"

enum class CmdLineSwitch
{
    Sensitivity,
    HookSensitivity,
    Pid,
    Log,
    Threads,
    Rules,
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

static void PrintHelp()
{
    wprintf(L"Help: memscan.exe [-sensitivity low|medium|high|off] [-hooks low|medium|high|off] [-pid ID] [-log path] [-threads N] [-rules rulesDir][dumpDirectory]\n"
        "\tdefault: low sensitivity all process scan without dumping, single thread\n");
}

static MemoryScanner::Sensitivity ParseSensitivity(const wchar_t* s)
{
    if (wcscmp(s, L"low") == 0)
        return MemoryScanner::Sensitivity::Low;
    else if (wcscmp(s, L"medium") == 0)
        return MemoryScanner::Sensitivity::Medium;
    else if (wcscmp(s, L"high") == 0)
        return MemoryScanner::Sensitivity::High;
    else if (wcscmp(s, L"off") == 0)
        return MemoryScanner::Sensitivity::Off;
    
    throw std::domain_error("");
}

int wmain(int argc, const wchar_t ** argv)
{
    std::wstring dumpsDir, rulesDir, logPath;
    MemoryScanner::Sensitivity sensitivity = MemoryScanner::Sensitivity::Low,
        hookSensitivity = MemoryScanner::Sensitivity::Low;
    std::wstring sensitivityString = L"low", hookSensitivityString = L"low";
    uint32_t pid = 0, threadsCount = 1;

    CmdLineSwitch state = CmdLineSwitch::None;
    for (int i = 1; i < argc; ++i)
    {
        try
        {
            if (argv[i][0] == L'-' || argv[i][0] == L'/')
            {
                if (wcscmp(argv[i] + 1, L"sensitivity") == 0)
                    state = CmdLineSwitch::Sensitivity;
                else if (wcscmp(argv[i] + 1, L"hooks") == 0)
                    state = CmdLineSwitch::HookSensitivity;
                else if (wcscmp(argv[i] + 1, L"pid") == 0)
                    state = CmdLineSwitch::Pid;
                else if (wcscmp(argv[i] + 1, L"log") == 0)
                    state = CmdLineSwitch::Log;
                else if (wcscmp(argv[i] + 1, L"threads") == 0)
                    state = CmdLineSwitch::Threads;
                else if (wcscmp(argv[i] + 1, L"rules") == 0)
                    state = CmdLineSwitch::Rules;
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
                case CmdLineSwitch::Sensitivity:
                {
                    sensitivity = ParseSensitivity(argv[i]);
                    sensitivityString = argv[i];
                    break;
                }
                case CmdLineSwitch::HookSensitivity:
                {
                    hookSensitivity = ParseSensitivity(argv[i]);
                    hookSensitivityString = argv[i];
                    break;
                }
                case CmdLineSwitch::Pid:
                    parse(argv[i], pid);
                    break;
                case CmdLineSwitch::Threads:
                    parse(argv[i], threadsCount);
                    break;
                case CmdLineSwitch::Log:
                    logPath = argv[i];
                    break;
                case CmdLineSwitch::None:
                    dumpsDir = argv[i];
                    break;
                case CmdLineSwitch::Rules:
                    rulesDir = argv[i];
                    break;
                default:
                    break;
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

    wprintf(L"Settings:\n\tsensitivity = %s\n\thook sensitivity = %s\n\tpid = %s\n\tlog = %s\n\tthreads = %u\n\trules directory = %s\n\tdump directory = %s\n\n", 
            sensitivityString.c_str(), hookSensitivityString.c_str(), pid == 0 ? L"all" : toString(pid).c_str(),
            logPath.empty() ? L"console" : logPath.c_str(),
            threadsCount == 0 ? std::thread::hardware_concurrency() : threadsCount,
            rulesDir.empty() ? L"none (prefedined set)" : rulesDir.c_str(),
            dumpsDir.empty() ? L"none" : dumpsDir.c_str());

    try
    {
        LoggerBase* logger = logPath.empty() ? (LoggerBase*)&ConsoleLogger::GetInstance() : (LoggerBase*)&FileLogger::GetInstance(logPath.c_str());
        SetDefaultLogger(logger);

        GetDefaultLogger()->Log(LoggerBase::Info, L">>> OS Architecture: %s <<<\n", GetOSArch() == CPUArchitecture::X64 ? L"X64" : L"X86");
        GetDefaultLogger()->Log(LoggerBase::Info, L">>> Scanner Architecture: %s <<<\n\n", sizeof(void*) == 8 ? L"X64" : L"X86");

        auto& scanner = MemoryScanner::GetInstance();
        if (rulesDir.empty())
            scanner.SetYaraRules(std::make_shared<YaraScanner::YaraRules>(predefinedRules));
        else
            scanner.SetYaraRules(std::make_shared<YaraScanner::YaraRules>(rulesDir.c_str()));

        Timer timer{ L"Memory" };
        scanner.Scan(std::make_shared<DefaultCallbacks>(pid, 0, 0, false, false, sensitivity, hookSensitivity, sensitivity, dumpsDir.c_str()), threadsCount);
    }
    catch (const std::exception& e)
    {
        wprintf(L"Error: %S\n", e.what());
        return 2;
    }

    return 0;
}
