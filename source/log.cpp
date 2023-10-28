#include "log.hpp"

#include <atomic>

void ConsoleLogger::Log(const wchar_t* message, ...)
{
	va_list args;
	va_start(args, message);
	vwprintf(message, args);
	va_end(args);
}

FileLogger::FileLogger(const wchar_t* path) : mBuffer(BufferSize), mFile(nullptr, fclose)
{
	FILE* f = nullptr;
	auto err = _wfopen_s(&f, path, L"wb");
	if (err != 0)
		throw std::exception{ "Unable to open file" };

	mBuffer.assign(BufferSize, 0);
	mFile.reset(f);
	const wchar_t bom = L'\xFEFF';
	_fwrite_nolock(&bom, sizeof(wchar_t), 1, f);
}

void FileLogger::Log(const wchar_t* message, ...)
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
