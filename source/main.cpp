#include <Windows.h>

#include <cstdio>
#include <sstream>
#include <stdexcept>

#include "scanner.h"

enum class CmdLineSwitch
{
    Sensitivity,
    Pid,
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

int wmain(int argc, const wchar_t ** argv)
{
    const wchar_t* dir = nullptr;
    uint32_t sensitivity = 0;
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
                else
                    throw std::invalid_argument("");
            }
            else
            {
                switch (state)
                {
                case CmdLineSwitch::Sensitivity:
                    parse(argv[i], sensitivity);
                    break;
                case CmdLineSwitch::Pid:
                    parse(argv[i], pid);
                    break;
                case CmdLineSwitch::None:
                    dir = argv[i];
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

    wprintf(L"Settings:\n\tsensitivity = %u\n\tpid = %s\n\tdump directory = %s\n\n", 
            (unsigned)sensitivity, pid == 0 ? L"all" : toString(pid).c_str(), 
            dir == nullptr ? L"None" : dir);
    wprintf(L"Found issues: %d\n", ScanMemory(sensitivity, pid, dir));

    return 0;
}
