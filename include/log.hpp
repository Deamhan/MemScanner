#pragma once

#include <cstdio>
#include <mutex>
#include <stdarg.h>
#include <vector>

class ILogger
{
public:
	virtual void Log(const wchar_t* message, ...) = 0;
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
	void Log(const wchar_t* message, ...) override;
	ConsoleLogger() = default;
};

class FileLogger : public ILogger
{
public:
	void Log(const wchar_t* message, ...) override;
	FileLogger(const wchar_t* path);

protected:
	std::vector<wchar_t> mBuffer;
	std::mutex mBufferGuard;
	std::unique_ptr<FILE, int(*)(FILE*)> mFile;

	const size_t BufferSize = 32 * 1024;
};

class NullLogger : public ILogger
{
public:
	void Log(const wchar_t*, ...) override {}
	NullLogger() = default;
};

FileLogger& GetFileLoggerInstance(const wchar_t* path);
ConsoleLogger& GetConsoleLoggerInstance();
NullLogger& GetNullLoggerInstance();

void SetDefaultLogger(ILogger* newLogger);
ILogger* GetDefaultLogger();
