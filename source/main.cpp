#include <Windows.h>

#include <cstdio>

#include "scanner.h"

int main(int argc, const char ** argv)
{
    wprintf(L"Found issues: %d\n", ScanMemory());

    return 0;
}
