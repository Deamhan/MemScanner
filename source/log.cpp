#include "stdafx.h"

#include "../include/log.hpp"

#include <atomic>
#include <iomanip>
#include <iostream>
#include <cinttypes>
#include <string>

#include <Windows.h>

using namespace SystemDefinitions;

void LoggerBase::Log(Level level, const wchar_t* message, ...)
{
    if (level < mMinimumLevel)
        return;

    va_list args;
    va_start(args, message);
    LogImpl(level, message, args);
    va_end(args);
}

void ConsoleLogger::LogImpl(LoggerBase::Level /*level*/, const wchar_t* message, va_list args)
{
	vwprintf(message, args);
}

FileLogger::FileLogger(const wchar_t* path, Level minLevel) 
    : LoggerBase(minLevel), mBuffer(BufferSize), mFile(nullptr, fclose)
{
	FILE* f = nullptr;
	_wfopen_s(&f, path, L"wb");
	if (f == nullptr)
		throw std::exception{ "Unable to open file" };

	mFile.reset(f);
	const wchar_t bom = L'\xFEFF';
	_fwrite_nolock(&bom, sizeof(wchar_t), 1, f);
}

void FileLogger::LogImpl(LoggerBase::Level /*level*/, const wchar_t* message, va_list args)
{
	std::unique_lock<std::mutex> lm(mBufferGuard);

	int len = vswprintf(mBuffer.data(), mBuffer.size() - 1, message, args);
	mBuffer[len] = L'\0';

	_fwrite_nolock(mBuffer.data(), sizeof(wchar_t), wcslen(mBuffer.data()), mFile.get());
}

FileLogger& FileLogger::GetInstance(const wchar_t* path)
{
	static FileLogger logger(path);
	return logger;
}

ConsoleLogger& ConsoleLogger::GetInstance()
{
	static ConsoleLogger logger{};
	return logger;
}

NullLogger& NullLogger::GetInstance()
{
	static NullLogger logger{};
	return logger;
}

MemoryLogger& MemoryLogger::GetInstance()
{
    static MemoryLogger logger{};
    return logger;
}

thread_local std::vector<wchar_t> MemoryLogger::lineBuffer(4096);
thread_local std::list<std::pair<std::wstring, LoggerBase::Level>> MemoryLogger::log;
std::mutex MemoryLogger::flushGuard;

void MemoryLogger::Flush(LoggerBase* target)
{
    std::lock_guard<std::mutex> lg(flushGuard);

    for (const auto& item : log)
        target->Log(item.second, L"%s", item.first.c_str());
    
    log.clear();
}

void MemoryLogger::LogImpl(MemoryLogger::Level level, const wchar_t* message, va_list args)
{
    int size = vswprintf(lineBuffer.data(), lineBuffer.size(), message, args);
    if (size != 0)
        log.emplace_back(std::wstring(lineBuffer.data(), size), level);
}

static std::atomic<LoggerBase*> defaultLogger = nullptr;
static thread_local LoggerBase* threadLocalDefaultLogger = nullptr;

void SetDefaultLogger(LoggerBase* newLogger)
{
	defaultLogger = newLogger;
}

void SetThreadLocalDefaultLogger(LoggerBase* newLogger)
{
    threadLocalDefaultLogger = newLogger;
}

LoggerBase* GetDefaultLogger()
{
	return defaultLogger;
}

LoggerBase* GetThreadLocalDefaultLogger()
{
    return threadLocalDefaultLogger;
}

LoggerBase* GetDefaultLoggerForThread()
{
    auto logger = GetThreadLocalDefaultLogger();
    if (logger != nullptr)
        return logger;

    return GetDefaultLogger();
}

struct DefaultLoggerInitializer
{
	DefaultLoggerInitializer()
	{
		SetDefaultLogger(&NullLogger::GetInstance());
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
void printMBI(const MEMORY_BASIC_INFORMATION_T<T>& mbi, LoggerBase::Level level, const wchar_t* offset)
{
    GetDefaultLoggerForThread()->Log(level, L"%s   BaseAddress:       0x%llx" LOG_ENDLINE_STR, offset, (unsigned long long)mbi.BaseAddress);
    GetDefaultLoggerForThread()->Log(level, L"%s   AllocationBase:    0x%llx" LOG_ENDLINE_STR, offset, (unsigned long long)mbi.AllocationBase);
    GetDefaultLoggerForThread()->Log(level, L"%s   AllocationProtect: %s" LOG_ENDLINE_STR, offset, ProtToStr(mbi.AllocationProtect).c_str());
    GetDefaultLoggerForThread()->Log(level, L"%s   RegionSize:        0x%llx" LOG_ENDLINE_STR, offset, mbi.RegionSize);
    GetDefaultLoggerForThread()->Log(level, L"%s   State:             %s" LOG_ENDLINE_STR, offset, stateToStr(mbi.State));
    GetDefaultLoggerForThread()->Log(level, L"%s   Protect:           %s" LOG_ENDLINE_STR, offset, ProtToStr(mbi.Protect).c_str());
    GetDefaultLoggerForThread()->Log(level, L"%s   Type:              %s" LOG_ENDLINE_STR, offset, typeToStr(mbi.Type));
    GetDefaultLoggerForThread()->Log(level, L"\n");
}

void storeMBI(const MEMORY_BASIC_INFORMATION_T<uint64_t>& mbi, std::wstringstream& storage, const wchar_t* offset)
{
    storage << std::hex 
        << offset << L"{\n"
        << offset << L"    \"BaseAddress\" : \""       << mbi.BaseAddress                  << L"\",\n"
        << offset << L"    \"AllocationBase\" : \""    << mbi.AllocationBase               << L"\",\n"
        << offset << L"    \"AllocationProtect\" : \"" << ProtToStr(mbi.AllocationProtect) << L"\",\n"
        << offset << L"    \"RegionSize\" : \""        << mbi.RegionSize                   << L"\",\n"
        << offset << L"    \"State\" : \""             << stateToStr(mbi.State)            << L"\",\n"
        << offset << L"    \"Protect\" : \""           << ProtToStr(mbi.Protect)           << L"\",\n"
        << offset << L"    \"Type\" : \""              << typeToStr(mbi.Type)              << L"\"\n"
        << offset << L"}";
}

template void printMBI(const MEMORY_BASIC_INFORMATION_T<uint32_t>& mbi, LoggerBase::Level level, const wchar_t* offset);
template void printMBI(const MEMORY_BASIC_INFORMATION_T<uint64_t>& mbi, LoggerBase::Level level, const wchar_t* offset);
