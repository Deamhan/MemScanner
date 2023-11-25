#include "log.hpp"

#include <atomic>
#include <iomanip>
#include <iostream>
#include <cinttypes>
#include <string>

#include <Windows.h>

using namespace SystemDefinitions;

void ConsoleLogger::Log(ILogger::Level /*level*/, const wchar_t* message, ...)
{
	va_list args;
	va_start(args, message);
	vwprintf(message, args);
	va_end(args);
}

FileLogger::FileLogger(const wchar_t* path) : mBuffer(BufferSize), mFile(nullptr, fclose)
{
	FILE* f = nullptr;
	_wfopen_s(&f, path, L"wb");
	if (f == nullptr)
		throw std::exception{ "Unable to open file" };

	mFile.reset(f);
	const wchar_t bom = L'\xFEFF';
	_fwrite_nolock(&bom, sizeof(wchar_t), 1, f);
}

void FileLogger::Log(ILogger::Level /*level*/, const wchar_t* message, ...)
{
	std::unique_lock<std::mutex> lm(mBufferGuard);

	va_list args;
	va_start(args, message);
	int len = vswprintf(mBuffer.data(), mBuffer.size() - 1, message, args);
	mBuffer[len] = L'\0';
	va_end(args);

	_fwrite_nolock(mBuffer.data(), sizeof(wchar_t), wcslen(mBuffer.data()), mFile.get());
}

FileLogger& GetFileLoggerInstance(const wchar_t* path)
{
	static FileLogger logger(path);
	return logger;
}

ConsoleLogger& GetConsoleLoggerInstance()
{
	static ConsoleLogger logger{};
	return logger;
}

NullLogger& GetNullLoggerInstance()
{
	static NullLogger logger{};
	return logger;
}

static std::atomic<ILogger*> defaultLogger;

void SetDefaultLogger(ILogger* newLogger)
{
	defaultLogger = newLogger;
}

ILogger* GetDefaultLogger()
{
	return defaultLogger;
}

struct DefaultLoggerInitializer
{
	DefaultLoggerInitializer()
	{
		SetDefaultLogger(&GetNullLoggerInstance());
	}
} loggerInitializer;

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

template <class T>
void printMBI(const MEMORY_BASIC_INFORMATION_T<T>& mbi, const wchar_t* offset)
{
    GetDefaultLogger()->Log(ILogger::Info, L"%s   BaseAddress:       0x%llx\n", offset, (unsigned long long)mbi.BaseAddress);
    GetDefaultLogger()->Log(ILogger::Info, L"%s   AllocationBase:    0x%llx\n", offset, (unsigned long long)mbi.AllocationBase);
    GetDefaultLogger()->Log(ILogger::Info, L"%s   AllocationProtect: %s\n", offset, ProtToStr(mbi.AllocationProtect).c_str());
    GetDefaultLogger()->Log(ILogger::Info, L"%s   RegionSize:        0x%llx\n", offset, mbi.RegionSize);
    GetDefaultLogger()->Log(ILogger::Info, L"%s   State:             %s\n", offset, stateToStr(mbi.State));
    GetDefaultLogger()->Log(ILogger::Info, L"%s   Protect:           %s\n", offset, ProtToStr(mbi.Protect).c_str());
    GetDefaultLogger()->Log(ILogger::Info, L"%s   Type:              %s\n", offset, typeToStr(mbi.Type));
    GetDefaultLogger()->Log(ILogger::Info, L"\n");
}

template void printMBI(const MEMORY_BASIC_INFORMATION_T<uint32_t>& mbi, const wchar_t* offset);
template void printMBI(const MEMORY_BASIC_INFORMATION_T<uint64_t>& mbi, const wchar_t* offset);
