#include <climits>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <system_error>
#include <vector>

#include "dump.hpp"
#include "log.hpp"
#include "memhelper.hpp"

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
static bool readValue(T& value, FILE* f) noexcept
{
    return fread(&value, sizeof(value), 1, f) == 1;
}

template <class T>
static bool readValue(std::vector<T>& value, FILE* f) noexcept
{
    return fread(value.data(), sizeof(T), value.size(), f) == value.size();
}

template <class T, int N>
static bool readValue(T (&value)[N], FILE* f) noexcept
{
    return fread(value, sizeof(T), N, f) == N;
}

template <class T>
static bool readDumpInfo(FILE* dump, const wchar_t* path, std::vector<MEMORY_BASIC_INFORMATION_T<T>>& mbiArray, std::vector<T>& threads)
{
    try
    {
        uint32_t threadCount = 0;
        if (!readValue(threadCount, dump))
            throw std::system_error(errno, std::iostream_category(), "");

        if (threadCount > MAX_THREADS_COUNT)
        {
            std::wcout << L"Error: to many threads " << threadCount << std::endl;
            return false;
        }

        threads.resize(threadCount);
        if (threadCount != 0)
        {
            if (!readValue(threads, dump))
                throw std::system_error(errno, std::iostream_category(), "");
        }

        uint32_t mbiCount = 0;
        if (!readValue(mbiCount, dump))
            throw std::system_error(errno, std::iostream_category(), "");

        if (mbiCount > MAX_MBI_COUNT)
        {
            std::wcout << L"Error: to many memory regions " << threadCount << std::endl;
            return false;
        }

        mbiArray.resize(mbiCount);
        if (!readValue(mbiArray, dump))
            throw std::system_error(errno, std::iostream_category(), "");

        return true;
    }
    catch (const std::system_error&)
    {
        std::wcout << L"Error: unable to read dump " << path << std::endl;
        return false;
    }
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

template <class T>
static void doList(const std::map<T, MBI_ENV_T<T>>& mapping, const std::vector<T>& threads)
{
    std::wstring type;
    if (!(std::wcin >> type))
        std::wcout << L"   Unable to get list type (use \'memory\' or \'threads\')" << std::endl;

    if (type == L"memory")
    {
        for (const auto& item : mapping)
            printMBI(*item.second.mbi);
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
    T address = 0;
    T allocAddress = 0;
    uint32_t attrMask = 0;

    enum class argType
    {
        Attr,
        Alloc,
        None
    } current = argType::None;

    do
    {
        std::wstring input;
        if (!(std::wcin >> input) || input.empty())
        {
            std::wcout << L"   Unable to get arg" << std::endl;
            return;
        }
        
        if (input[0] == L'-' || input[0] == L'/')
        {
            auto argTypeStr = input.substr(1);
            if (argTypeStr == L"alloc")
                current = argType::Alloc;
            else if (argTypeStr == L"attr")
                current = argType::Attr;
            else
            {
                std::wcout << L"   Unknown argument: " << argTypeStr << std::endl;
                return;
            }
        }
        else
        {
            switch (current)
            {
            case argType::Attr:
            {
                for (const auto c : input)
                {
                    switch (c)
                    {
                    case L'R':
                    case L'r':
                        attrMask |= MemoryHelper<CPUArchitecture::X86>::RFlag;
                        break;
                    case L'W':
                    case L'w':
                        attrMask |= MemoryHelper<CPUArchitecture::X86>::WFlag;
                        break;
                    case L'X':
                    case L'x':
                        attrMask |= MemoryHelper<CPUArchitecture::X86>::XFlag;
                        break;
                    default:
                        std::wcout << L"   Unknown attribute: " << c << std::endl;
                        return;
                    }
                }
                
                break;
            } 
            case argType::Alloc:
            {
                std::wstringstream ss(input);
                if (!(ss >> std::hex >> allocAddress))
                {
                    std::wcout << L"   Unable to get arg" << std::endl;
                    return;
                }
                break;
            }
            case argType::None:
            {
                std::wstringstream ss(input);
                if (!(ss >> std::hex >> address))
                {
                    std::wcout << L"   Unable to get arg" << std::endl;
                    return;
                }
                break;
            }
            default:
                break;
            }

            break;
        }
    } while (true);
    
    if (address != 0)
    {
        const auto it = mapping.upper_bound(address);
        if (it == mapping.end() || address < it->second.mbi->BaseAddress)
            std::wcout << L"   Not found" << std::endl;
        else
            printMBI(*it->second.mbi);
    }
    else if (allocAddress != 0)
    {
        auto it = mapping.upper_bound(allocAddress);
        if (it == mapping.end())
            std::wcout << L"   Not found" << std::endl;
        else
        {
            const auto end = mapping.end();
            for (; it != end && it->second.mbi->AllocationBase == allocAddress; ++it)
                printMBI(*it->second.mbi);
        }
    }
    else
    {
        for (const auto& item : mapping)
        {
            if ((MemoryHelperBase::protToFlags(item.second.mbi->AllocationProtect) & attrMask) == attrMask 
                || (MemoryHelperBase::protToFlags(item.second.mbi->Protect) & attrMask) == attrMask)
                printMBI(*item.second.mbi);
        }
    }
    
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

static void printHelp()
{
    std::wcout <<
        L"   Supported commands:\n"
        L"     list memory|thread - prints all memory or thread information\n\n"
        L"     match <-attr|-alloc> address - prints information about memory region which address (hex) belongs to\n"
        L"       -alloc switch enables filtering according AllocationBase field\n"
        L"       -attr switch enables filtering according AllocationProtect and Protect fields\n\n"
        L"     offset address - prints offset in dump file that matches the address (hex)\n\n"
        L"     help - prints this help\n\n"
        L"     exit - exit from dump viewer\n"
        << std::endl;
    FlushInput();
}

template <class T>
static bool doProcessing(FILE* dump, const wchar_t* path, uint8_t processBitness)
{
    std::wcout << L"Process Architecture: " << (processBitness == 64 ? L"X64" : L"X86") << std::endl;
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
        {
            std::wcout << L"   Bye!" << std::endl;
            break;
        }
        else if (cmd == L"offset")
            doOffset(mapping);
        else if (cmd == L"help")
            printHelp();
        else
        {
            std::wcout << L"   Unknown command: \'" << cmd << L"\'" << std::endl;
            FlushInput();
        }  
    } while (true);

    return true;
}

static bool processDump(FILE * dump, const wchar_t* path)
{
    try
    {
        char sig[sizeof(DumpSignature)];
        if (!readValue(sig, dump))
            throw std::system_error(errno, std::iostream_category(), "");

        if (memcmp(sig, DumpSignature, sizeof(DumpSignature)) != 0)
            throw std::logic_error("");

        uint8_t osBitness = 0;
        if (!readValue(osBitness, dump))
            throw std::system_error(errno, std::iostream_category(), "");

        uint8_t procBitness = 0;
        if (!readValue(procBitness, dump))
            throw std::system_error(errno, std::iostream_category(), "");

        if (procBitness != 32 && procBitness != 64)
            throw std::logic_error("");

        switch (osBitness)
        {
        case 32:
            std::wcout << L"OS Architecture: X86" << std::endl;
            return doProcessing<uint32_t>(dump, path, procBitness);
        case 64:
            std::wcout << L"OS Architecture: X64" << std::endl;
            return doProcessing<uint64_t>(dump, path, procBitness);
        default:
            throw std::logic_error("");
        }
    }
    catch (const std::system_error&)
    {
        std::wcout << L"Error: unable to read dump " << path << std::endl;
        return false;
    }
    catch (const std::logic_error&)
    {
        std::wcout << L"Error: invalid dump file" << path << std::endl;
        return false;
    }
}

int wmain(int argc, const wchar_t** argv)
{
    std::ios::sync_with_stdio();

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

    SetDefaultLogger(&GetConsoleLoggerInstance());

    std::unique_ptr<FILE, int(*)(FILE*)> dumpGurad(dump, fclose);
    return processDump(dump, argv[1]) ? 0 : 1;
}
