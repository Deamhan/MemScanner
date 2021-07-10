#include <Windows.h>

#include <cstdio>

#include "scanner.h"

int wmain(int argc, const wchar_t ** argv)
{
    const wchar_t* dir = nullptr;
    if (argc > 1)
        dir = argv[1];

    wprintf(L"Found issues: %d\n", ScanMemory(dir));

    return 0;
}
