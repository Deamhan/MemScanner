#pragma once

#include <chrono>
#include <cstdio>
#include <list>
#include <mutex>
#include <stdarg.h>
#include <utility>
#include <vector>

#include "system_defs.hpp"

class LoggerBase
{
public:
	enum Level
	{
		Debug,
		Info,
		Error
	};

	void Log(Level level, const wchar_t* message, ...);
	void SetMinimalLevel(Level minLevel) noexcept { mMinimumLevel = minLevel; }
	Level GetMinimalLevel() const noexcept { return mMinimumLevel; }

	virtual ~LoggerBase() = default;

protected:
	LoggerBase(const LoggerBase&) = delete;
	LoggerBase(LoggerBase&&) = delete;
	LoggerBase& operator = (const LoggerBase&) = delete;
	LoggerBase& operator = (LoggerBase&&) = delete;

	LoggerBase(Level minLevel) noexcept : mMinimumLevel(minLevel) {}

	virtual void LogImpl(Level level, const wchar_t* message, va_list args) = 0;

	Level mMinimumLevel;
};

class ConsoleLogger : public LoggerBase
{
public:
	static ConsoleLogger& GetInstance();

protected:
    void LogImpl(Level level, const wchar_t* message, va_list args) override;
	ConsoleLogger(Level minLevel = Debug) : LoggerBase(minLevel) {}
};

class FileLogger : public LoggerBase
{
public:
	static FileLogger& GetInstance(const wchar_t* path);

protected:
	const size_t BufferSize = 32 * 1024;

	std::vector<wchar_t> mBuffer;
	std::mutex mBufferGuard;
	std::unique_ptr<FILE, int(*)(FILE*)> mFile;

    void LogImpl(Level level, const wchar_t* message, va_list args) override;

	FileLogger(const wchar_t* path, Level minLevel = Debug);
};

class NullLogger : public LoggerBase
{
public:
	static NullLogger& GetInstance();

private:
	NullLogger(Level minLevel = Debug) : LoggerBase(minLevel) {}

	void LogImpl(Level /*level*/, const wchar_t* /*message*/ , va_list /*args*/ ) override {}
};

LoggerBase* GetDefaultLogger();

LoggerBase* GetThreadLocalDefaultLogger();
void SetThreadLocalDefaultLogger(LoggerBase* newLogger);

class MemoryLogger : public LoggerBase
{
public:
	void Flush(LoggerBase* target);

	static MemoryLogger& GetInstance();

	class AutoFlush
	{
	public:
		AutoFlush(MemoryLogger& logger) noexcept: mLogger(logger)
		{}

		~AutoFlush()
		{
			mLogger.Flush(GetDefaultLogger());
			SetThreadLocalDefaultLogger(nullptr); // let's switch to global log
		}

	private:
		MemoryLogger& mLogger;
	};

private:
	static thread_local std::list<std::pair<std::wstring, Level>> log;
	static thread_local std::vector<wchar_t> lineBuffer;
	static std::mutex flushGuard;

	void LogImpl(Level level, const wchar_t* message, va_list args) override;

	MemoryLogger(Level minLevel = Debug) : LoggerBase(minLevel) {}
};

void SetDefaultLogger(LoggerBase* newLogger);

LoggerBase* GetDefaultLoggerForThread();

#ifndef LOG_ENDLINE_STR
#define LOG_ENDLINE_STR L"\n"
#endif // LOG_ENDLINE_STR

class Timer
{
public:
	Timer(const wchar_t* name = L"") : mBegin(std::chrono::high_resolution_clock::now()), mName(name)
	{}

	~Timer()
	{
		auto end = std::chrono::high_resolution_clock::now();
		auto ticks = (end - mBegin).count();

		GetDefaultLoggerForThread()->Log(LoggerBase::Debug,  L"\nTime spent (%s): %lld us" LOG_ENDLINE_STR, mName.c_str(), ticks / 1000);
	}

private:
	std::chrono::time_point<std::chrono::high_resolution_clock> mBegin;
	std::wstring mName;
};

const std::wstring ProtToStr(uint32_t prot);

template <class T>
void printMBI(const SystemDefinitions::MEMORY_BASIC_INFORMATION_T<T>& mbi, LoggerBase::Level level, const wchar_t* offset = L"");
