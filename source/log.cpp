#include "log.hpp"

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
	auto err = _wfopen_s(&f, path, L"wt");
	if (err != 0)
		throw std::exception{ "Unable to open file" };

	mFile.reset(f);
}

void FileLogger::Log(const wchar_t* message, ...)
{
	std::unique_lock<std::mutex> lm(mBufferGuard);

	va_list args;
	va_start(args, message);
	int len = vswprintf(mBuffer.data(), mBuffer.size() - 1, message, args);
	mBuffer[len] = L'\0';
	va_end(args);

	_fwrite_nolock(mBuffer.data(), sizeof(wchar_t), len, mFile.get());
}

ILogger& GetLoggerInstance(LoggerType type)
{
	static NullLogger nullLogger;
	static ConsoleLogger consoleLogger;

	switch (type)
	{
	case LoggerType::None:
		return nullLogger;
	case LoggerType::Console:
		return consoleLogger;
	case LoggerType::File:
		return nullLogger;
	default:
		return nullLogger;
	}
}
