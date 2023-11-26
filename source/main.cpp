#include <Windows.h>

#include <cstdio>
#include <sstream>
#include <stdexcept>

#include "log.hpp"
#include "scanner.hpp"

enum class CmdLineSwitch
{
    Sensitivity,
    Pid,
    Log,
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

void PrintHelp()
{
    wprintf(L"Help: memscan.exe [-sensitivity low|medium|high] [-pid ID] [-log path] [dumpDirectory]\n"
        "\tdefault: low sensitivity all process scan without dumping\n");
}

int wmain(int argc, const wchar_t ** argv)
{
    std::wstring dumpsDir= L"";
    const wchar_t* logPath = nullptr;
    MemoryScanner::Sensitivity sensitivity = MemoryScanner::Low;
    std::wstring sensitivityString = L"low";
    uint32_t pid = 0;

    CmdLineSwitch state = CmdLineSwitch::None;
    for (int i = 1; i < argc; ++i)
    {
        try
        {
            if (argv[i][0] == L'-' || argv[i][0] == L'/')
            {
                if (wcscmp(argv[i] + 1, L"sensitivity") == 0)
                    state = CmdLineSwitch::Sensitivity;
                else if (wcscmp(argv[i] + 1, L"pid") == 0)
                    state = CmdLineSwitch::Pid;
                else if (wcscmp(argv[i] + 1, L"log") == 0)
                    state = CmdLineSwitch::Log;
                else if (wcscmp(argv[i] + 1, L"help") == 0)
                {
                    
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
                    if (wcscmp(argv[i], L"low") == 0)
                        sensitivity = MemoryScanner::Low;
                    else if (wcscmp(argv[i], L"medium") == 0)
                        sensitivity = MemoryScanner::Medium;
                    else if (wcscmp(argv[i], L"high") == 0)
                        sensitivity = MemoryScanner::High;
                    else
                        throw std::domain_error("");

                    sensitivityString = argv[i];
                    break;
                }
                case CmdLineSwitch::Pid:
                    parse(argv[i], pid);
                    break;
                case CmdLineSwitch::Log:
                    logPath = argv[i];
                    break;
                case CmdLineSwitch::None:
                    dumpsDir = argv[i];
                    break;
                default:
                    break;
                }

                state = CmdLineSwitch::None;
            }
        }
        catch (const std::invalid_argument&)
        {
            wprintf(L"Unknown switch: %s\n", argv[i] + 1);
            return 1;
        }
        catch (const std::domain_error&)
        {
            wprintf(L"Invalid argument: %s\n", argv[i]);
            return 1;
        }
    }

    wprintf(L"Settings:\n\tsensitivity = %s\n\tpid = %s\n\tlog = %s\n\tdump directory = %s\n\n", 
            sensitivityString.c_str(), pid == 0 ? L"all" : toString(pid).c_str(),
            logPath == nullptr ? L"console" : logPath,
            dumpsDir.empty() ? L"none" : dumpsDir.c_str());

    try
    {
        ILogger* logger = logPath == nullptr ? (ILogger*)&GetConsoleLoggerInstance() : (ILogger*)&GetFileLoggerInstance(logPath);
        SetDefaultLogger(logger);

        MemoryScanner scanner { sensitivity };
        auto callbacks = std::make_shared<MemoryScanner::DefaultCallbacks>();
        callbacks->SetDumpsRoot(dumpsDir.c_str());
        scanner.Scan(pid);
    }
    catch (const std::exception& e)
    {
        wprintf(L"Error: %S\n", e.what());
        return 2;
    }

    return 0;
}
