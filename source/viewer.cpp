#include <climits>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "dump.h"
#include "system_defs.h"

#undef max

static const uint32_t MAX_THREADS_COUNT = 1024 * 1024;
static const uint32_t MAX_MBI_COUNT = 16 * 1024 * 1024;

using namespace SystemDefinitions;

template <class T>
struct MBI_ENV_T
{
    T offset;
    const MEMORY_BASIC_INFORMATION_T<T> * mbi;
};

template <class T>
static bool readDumpInfo(FILE* dump, const wchar_t* path, std::vector<MEMORY_BASIC_INFORMATION_T<T>>& mbiArray, std::vector<T>& threads)
{
    uint32_t threadCount = 0;
    if (fread(&threadCount, sizeof(threadCount), 1, dump) != 1)
    {
        std::wcout << L"Error: unable to read dump " << path << std::endl;
        return false;
    }

    if (threadCount > MAX_THREADS_COUNT)
    {
        std::wcout << L"Error: to many threads " << threadCount << std::endl;
        return false;
    }

    threads.resize(threadCount);
    if (fread(threads.data(), sizeof(T), threadCount, dump) != threadCount)
    {
        std::wcout << L"Error: unable to read dump " << path << std::endl;
        return false;
    }

    typename MEMORY_BASIC_INFORMATION_T<T> MBI;
    uint32_t mbiCount = 0;
    if (fread(&mbiCount, sizeof(mbiCount), 1, dump) != 1)
    {
        std::wcout << L"Error: unable to read dump " << path << std::endl;
        return false;
    }

    if (mbiCount > MAX_MBI_COUNT)
    {
        std::wcout << L"Error: to many memory regions " << threadCount << std::endl;
        return false;
    }

    mbiArray.resize(mbiCount);
    if (fread(mbiArray.data(), sizeof(MBI), mbiCount, dump) != mbiCount)
    {
        std::wcout << L"Error: unable to read dump " << path << std::endl;
        return false;
    }

    return true;
}

template <class T>
static std::map<T, MBI_ENV_T<T>> parseDumpInfo(const std::vector<MEMORY_BASIC_INFORMATION_T<T>>& mbiArray, T initOffset)
{
    std::map<T, MBI_ENV_T<T>> dataMapping;
    T offset = initOffset;
    for (const auto& mbi : mbiArray)
    {
        MBI_ENV_T<T> env = { offset, &mbi };
        offset += mbi.RegionSize;
        dataMapping.emplace(mbi.BaseAddress + mbi.RegionSize, env);
    }

    return dataMapping;
}

static void FlushInput()
{
    std::wcin.clear();
    std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), L'\n');
}

static const std::wstring protToStr(uint32_t prot)
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

template <class T>
static void printMBI(const MEMORY_BASIC_INFORMATION_T<T>* mbi)
{
    std::wcout << L"   BaseAddress:       " << std::hex << mbi->BaseAddress << std::endl;
    std::wcout << L"   AllocationBase:    " << std::hex << mbi->AllocationBase << std::endl;
    std::wcout << L"   AllocationProtect: " << protToStr(mbi->AllocationProtect) << std::endl;
    std::wcout << L"   RegionSize:        " << std::hex << mbi->RegionSize << std::endl;
    std::wcout << L"   State:             " << stateToStr(mbi->State) << std::endl;
    std::wcout << L"   Protect:           " << protToStr(mbi->Protect) << std::endl;
    std::wcout << L"   Type:              " << typeToStr(mbi->Type) << std::endl;
    std::wcout << std::endl;
}

template <class T>
static void doList(const std::map<T, MBI_ENV_T<T>>& mapping, const std::vector<T>& threads)
{
    std::wstring type;
    if (!(std::wcin >> type))
        std::wcout << L"   Unable to get list type (use \'memory\' or \'threads\')" << std::endl;

    if (type == L"memory")
    {
        for (const auto& item : mapping)
            printMBI(item.second.mbi);
    }
    else if (type == L"threads")
    {
        for (const auto item : threads)
            std::wcout << L"   Entry point: " << std::hex << item << std::endl;
    }
    else
        std::wcout << L"   Unknown list type: " << type <<  L" (use \'memory\' or \'threads\')" << std::endl;

    std::wcout << std::endl;
    FlushInput();
}

template <class T>
static void doMatch(const std::map<T, MBI_ENV_T<T>>& mapping)
{
    T address;
    if (!(std::wcin >> std::hex >> address))
        std::wcout << L"   Unable to get address" << std::endl;

    const auto it = mapping.upper_bound(address);
    if (it == mapping.end() || address < it->second.mbi->BaseAddress)
        std::wcout << L"   Not found" << std::endl;
    else
        printMBI(it->second.mbi);

    std::wcout << std::endl;
    FlushInput();
}

template <class T>
static void doOffset(const std::map<T, MBI_ENV_T<T>>& mapping)
{
    T address;
    if (!(std::wcin >> std::hex >> address))
        std::wcout << L"   Unable to get address" << std::endl;

    const auto it = mapping.upper_bound(address);
    if (it == mapping.end() || address < it->second.mbi->BaseAddress)
        std::wcout << L"   Not found" << std::endl;
    else
    {
        T delta = address - it->second.mbi->BaseAddress;
        std::wcout << L"   " << std::hex << (it->second.offset + delta) << std::endl;
    }
        

    std::wcout << std::endl;
    FlushInput();
}

template <class T>
static bool doProcessing(FILE* dump, const wchar_t* path)
{
    std::vector<MEMORY_BASIC_INFORMATION_T<T>> mbiArray;
    std::vector<T> threads;
    if (!readDumpInfo(dump, path, mbiArray, threads))
        return false;

    const auto mapping = parseDumpInfo<T>(mbiArray, ftell(dump));

    do
    {
        std::wcout << L"> ";
        std::wstring cmd;
        if (!(std::wcin >> cmd))
            return true;

        if (cmd == L"list")
            doList(mapping, threads);
        else if (cmd == L"match")
            doMatch(mapping);
        else if (cmd == L"exit")
            break;
        else if (cmd == L"offset")
            doOffset(mapping);
        else
            std::wcout << L"   Unknown command: \'" << cmd << L"\'" << std::endl;
    } while (true);

    return true;
}

static bool processDump(FILE * dump, const wchar_t* path)
{
    char sig[sizeof(DumpSignature)];
    if (fread(sig, 1, sizeof(DumpSignature), dump) != sizeof(DumpSignature))
    {
        std::wcout << "Error: unable to read dump " << path << std::endl;
        return false;
    }

    if (memcmp(sig, DumpSignature, sizeof(DumpSignature)) != 0)
    {
        std::wcout << "Error: invalid dump file" << path << std::endl;
        return false;
    }
        
    uint8_t bitness = 0;
    if (fread(&bitness, sizeof(bitness), 1, dump) != 1)
    {
        std::wcout << "Error: unable to read dump " << path << std::endl;
        return false;
    }

    switch (bitness)
    {
    case 32:
        std::wcout << "OS Architecture: X86" << std::endl;
        return doProcessing<uint32_t>(dump, path);
    case 64:
        std::wcout << "OS Architecture: X86" << std::endl;
        return doProcessing<uint64_t>(dump, path);
    default:
        std::wcout << "Error: invalid dump file" << path << std::endl;
        return false;
    }
}

int wmain(int argc, const wchar_t** argv)
{
    if (argc < 2)
    {
        std::wcout << L"Usage: viewer path_to_dump" << std::endl;
        return 1;
    }

    FILE* dump = nullptr;
    _wfopen_s(&dump, argv[1], L"rb");
    if (dump == nullptr)
    {
        std::wcout << "Error: unable to open dump " << argv[1] << std::endl;
        return 1;
    }

    std::unique_ptr<FILE, int(*)(FILE*)> dumpGurad(dump, fclose);
    return processDump(dump, argv[1]) ? 0 : 1;
}
