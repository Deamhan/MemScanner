#pragma once

#include <chrono>
#include <cstdio>
#include <list>
#include <mutex>
#include <stdarg.h>
#include <utility>
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

	static ConsoleLogger& GetInstance();

private:
	ConsoleLogger() = default;
};

class FileLogger : public ILogger
{
public:
	void Log(Level level, const wchar_t* message, ...) override;

	static FileLogger& GetInstance(const wchar_t* path);

protected:
	const size_t BufferSize = 32 * 1024;

	std::vector<wchar_t> mBuffer;
	std::mutex mBufferGuard;
	std::unique_ptr<FILE, int(*)(FILE*)> mFile;

	FileLogger(const wchar_t* path);
};

class NullLogger : public ILogger
{
public:
	void Log(Level, const wchar_t*, ...) override {}

	static NullLogger& GetInstance();

private:
	NullLogger() = default;
};

ILogger* GetDefaultLogger();

class MemoryLogger : public ILogger
{
public:
	void Log(Level, const wchar_t*, ...) override;
	void Flush(ILogger* target);

	static MemoryLogger& GetInstance();

	class AutoFlush
	{
	public:
		AutoFlush(MemoryLogger& logger) noexcept: mLogger(logger)
		{}

		~AutoFlush()
		{
			mLogger.Flush(GetDefaultLogger());
		}

	private:
		MemoryLogger& mLogger;
	};

private:
	static thread_local std::list<std::pair<std::wstring, Level>> log;
	static thread_local std::vector<wchar_t> lineBuffer;
	static std::mutex flushGuard;

	MemoryLogger() = default;
};

void SetDefaultLogger(ILogger* newLogger);

ILogger* GetThreadLocalDefaultLogger();
void SetThreadLocalDefaultLogger(ILogger* newLogger);

ILogger* GetDefaultLoggerForThread();

class Timer
{
public:
	Timer(const wchar_t* name = L"") : mBegin(std::chrono::high_resolution_clock::now()), mName(name)
	{}

	~Timer()
	{
		auto end = std::chrono::high_resolution_clock::now();
		auto ticks = (end - mBegin).count();

		GetDefaultLoggerForThread()->Log(ILogger::Debug,  L"\nTime spent (%s): %lld us\n", mName.c_str(), ticks / 1000);
	}

private:
	std::chrono::time_point<std::chrono::high_resolution_clock> mBegin;
	std::wstring mName;
};

const std::wstring ProtToStr(uint32_t prot);

template <class T>
void printMBI(const SystemDefinitions::MEMORY_BASIC_INFORMATION_T<T>& mbi, const wchar_t* offset = L"");
