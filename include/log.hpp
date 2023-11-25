#pragma once

#include <chrono>
#include <cstdio>
#include <mutex>
#include <stdarg.h>
#include <vector>

#include "system_defs.hpp"

class ILogger
{
public:
	enum Level
	{
		Debug,
		Info,
		Error
	};

	virtual void Log(Level level, const wchar_t* message, ...) = 0;
	virtual ~ILogger() = default;

protected:
	ILogger(const ILogger&) = delete;
	ILogger(ILogger&&) = delete;
	ILogger& operator = (const ILogger&) = delete;
	ILogger& operator = (ILogger&&) = delete;

	ILogger() = default;
};

class ConsoleLogger : public ILogger
{
public:
	void Log(Level level, const wchar_t* message, ...) override;
	ConsoleLogger() = default;
};

class FileLogger : public ILogger
{
public:
	void Log(Level level, const wchar_t* message, ...) override;
	FileLogger(const wchar_t* path);

protected:
	const size_t BufferSize = 32 * 1024;

	std::vector<wchar_t> mBuffer;
	std::mutex mBufferGuard;
	std::unique_ptr<FILE, int(*)(FILE*)> mFile;
};

class NullLogger : public ILogger
{
public:
	void Log(Level, const wchar_t*, ...) override {}
	NullLogger() = default;
};

FileLogger& GetFileLoggerInstance(const wchar_t* path);
ConsoleLogger& GetConsoleLoggerInstance();
NullLogger& GetNullLoggerInstance();

void SetDefaultLogger(ILogger* newLogger);
ILogger* GetDefaultLogger();

class Timer
{
public:
	Timer(const wchar_t* name = L"") : mBegin(std::chrono::high_resolution_clock::now()), mName(name)
	{}

	~Timer()
	{
		auto end = std::chrono::high_resolution_clock::now();
		auto ticks = (end - mBegin).count();

		GetDefaultLogger()->Log(ILogger::Debug,  L"\nTime spent (%s): %lld us\n", mName.c_str(), ticks / 1000);
	}

private:
	std::chrono::time_point<std::chrono::high_resolution_clock> mBegin;
	std::wstring mName;
};

const std::wstring ProtToStr(uint32_t prot);

template <class T>
void printMBI(const SystemDefinitions::MEMORY_BASIC_INFORMATION_T<T>& mbi, const wchar_t* offset = L"");
