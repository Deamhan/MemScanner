#include "file.hpp"

ReadOnlyFile::ReadOnlyFile(const wchar_t* path, size_t bufferSize) : ReadOnlyDataSource(bufferSize), mLastError(ERROR_SUCCESS)
{
	mFileHandle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (mFileHandle == INVALID_HANDLE_VALUE)
		throw FileException{ DataSourceError::UnableToOpen, GetLastError() };
}

void ReadOnlyFile::ReadImpl(void* buffer, size_t bufferLength, size_t& read)
{
	read = 0;
	DWORD bytesRead = 0;
	if (FALSE == ReadFile(mFileHandle, buffer, (DWORD)bufferLength, &bytesRead, nullptr))
		throw FileException{ DataSourceError::UnableToRead, GetLastError() };

	read = bytesRead;
}

void ReadOnlyFile::SeekImpl(uint64_t newOffset)
{
	LARGE_INTEGER newLargeIntPointer, newPointer;
	newLargeIntPointer.QuadPart = newOffset;
	if (SetFilePointerEx(mFileHandle, newLargeIntPointer, &newPointer, FILE_BEGIN) == FALSE)
		throw FileException{ DataSourceError::InvalidOffset, GetLastError() };
}

void ReadOnlyFile::GetSizeImpl(uint64_t& size)
{
	LARGE_INTEGER largeIntSize;
	auto result = GetFileSizeEx(mFileHandle, &largeIntSize);
	if (result == FALSE)
		throw FileException{ DataSourceError::UnableToGetSize, GetLastError() };

	size = largeIntSize.QuadPart;
}
