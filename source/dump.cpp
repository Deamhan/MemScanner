#include "dump.hpp"

#include <iomanip>
#include <iostream>
#include <cinttypes>
#include <string>

#include <Windows.h>

#include "log.hpp"

using namespace SystemDefinitions;

const std::wstring ProtToStr(uint32_t prot)
{
    std::wstring result;

    switch (prot & 0xff)
    {
    case PAGE_EXECUTE:
        result = L"X";
        break;
    case PAGE_EXECUTE_READ:
        result = L"RX";
        break;
    case PAGE_EXECUTE_READWRITE:
        result = L"RWX";
        break;
    case PAGE_EXECUTE_WRITECOPY:
        result = L"RW(c)X";
        break;
    case PAGE_NOACCESS:
        result = L"-";
        break;
    case PAGE_READONLY:
        result = L"R";
        break;
    case PAGE_READWRITE:
        result = L"RW";
        break;
    case PAGE_WRITECOPY:
        result = L"RW(c)";
        break;
    default:
        return L"Unknown";
    }

    if (prot & PAGE_GUARD)
        result += L"+G";

    if (prot & PAGE_NOCACHE)
        result += L"+NC";

    if (prot & PAGE_WRITECOMBINE)
        result += L"+WC";

    return result;
}

static const wchar_t* typeToStr(MemType type)
{
    switch (type)
    {
    case MemType::Image:
        return L"Image";
    case MemType::Mapped:
        return L"Mapped";
    case MemType::Private:
        return L"Private";
    default:
        return L"Invalid";
    }
}

static const wchar_t* stateToStr(uint32_t state)
{
    switch (state)
    {
    case MEM_COMMIT:
        return L"Commit";
    case MEM_FREE:
        return L"Free";
    case MEM_RESERVE:
        return L"Reserve";
    default:
        return L"Invalid";
    }
}

const uint32_t protToFlags(uint32_t prot)
{
    switch (prot & 0xff)
    {
    case PAGE_EXECUTE:
        return XFlag;
    case PAGE_EXECUTE_READ:
        return XFlag | RFlag;
    case PAGE_EXECUTE_READWRITE:
        return XFlag | RFlag | WFlag;
    case PAGE_EXECUTE_WRITECOPY:
        return XFlag | RFlag | WFlag;
    case PAGE_NOACCESS:
        return 0;
    case PAGE_READONLY:
        return RFlag;
    case PAGE_READWRITE:
        return RFlag | WFlag;
    case PAGE_WRITECOPY:
        return RFlag | WFlag;
    default:
        return XFlag | RFlag | WFlag;
    }
}

template <class T>
void printMBI(const MEMORY_BASIC_INFORMATION_T<T>& mbi, const wchar_t* offset)
{
    GetDefaultLogger()->Log(L"%s   BaseAddress:       0x%llu\n", offset, (unsigned long long)mbi.BaseAddress);
    GetDefaultLogger()->Log(L"%s   AllocationBase:    0x%llu\n", offset, (unsigned long long)mbi.AllocationBase);
    GetDefaultLogger()->Log(L"%s   AllocationProtect: %s\n",     offset, ProtToStr(mbi.AllocationProtect).c_str());
    GetDefaultLogger()->Log(L"%s   RegionSize:        0x%llu\n", offset, mbi.RegionSize);
    GetDefaultLogger()->Log(L"%s   State:             %s\n",     offset, stateToStr(mbi.State));
    GetDefaultLogger()->Log(L"%s   Protect:           %s\n",     offset, ProtToStr(mbi.Protect).c_str());
    GetDefaultLogger()->Log(L"%s   Type:              %s\n",     offset, typeToStr(mbi.Type));
    GetDefaultLogger()->Log(L"\n");
}

template void printMBI(const MEMORY_BASIC_INFORMATION_T<uint32_t>& mbi, const wchar_t* offset);
template void printMBI(const MEMORY_BASIC_INFORMATION_T<uint64_t>& mbi, const wchar_t* offset);
