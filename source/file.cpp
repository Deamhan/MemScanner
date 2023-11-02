#include "file.hpp"

File::File(const wchar_t* path, bool readOnly, size_t bufferSize) : DataSource(bufferSize), mLastError(ERROR_SUCCESS)
{
	mFileHandle = CreateFileW(path, GENERIC_READ | (readOnly ? 0 : GENERIC_WRITE), FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (mFileHandle == INVALID_HANDLE_VALUE)
		throw FileException{ DataSourceError::UnableToOpen, GetLastError() };
}

size_t File::ReadImpl(void* buffer, size_t bufferLength)
{
	DWORD bytesRead = 0;
	if (FALSE == ReadFile(mFileHandle, buffer, (DWORD)bufferLength, &bytesRead, nullptr))
		throw FileException{ DataSourceError::UnableToRead, GetLastError() };

	return bytesRead;
}

size_t File::WriteImpl(const void* buffer, size_t bufferLength)
{
	DWORD bytesWritten = 0;
	if (FALSE == WriteFile(mFileHandle, buffer, (DWORD)bufferLength, &bytesWritten, nullptr))
		throw FileException{ DataSourceError::UnableToWrite, GetLastError() };

	return bytesWritten;
}

void File::SeekImpl(uint64_t newOffset)
{
	LARGE_INTEGER newLargeIntPointer, newPointer;
	newLargeIntPointer.QuadPart = newOffset;
	if (SetFilePointerEx(mFileHandle, newLargeIntPointer, &newPointer, FILE_BEGIN) == FALSE)
		throw FileException{ DataSourceError::InvalidOffset, GetLastError() };
}

uint64_t File::GetSizeImpl() const
{
	LARGE_INTEGER largeIntSize;
	auto result = GetFileSizeEx(mFileHandle, &largeIntSize);
	if (result == FALSE)
		throw FileException{ DataSourceError::UnableToGetSize, GetLastError() };

	return largeIntSize.QuadPart;
}
