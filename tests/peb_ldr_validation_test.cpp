#include "memhelper.hpp"

int main()
{
    const auto& helper = GetMemoryHelper();
    auto addr = (uintptr_t)GetModuleHandleW(L"ntdll");

    bool found = false;
    if (!helper.IsModuleKnownByPeb(GetCurrentProcess(), addr + 0x1000, found))
        return 1;

    return found ? 0 : 2;
}
