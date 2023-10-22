#include "file.hpp"

ReadOnlyFile::ReadOnlyFile(const wchar_t* path, size_t bufferSize) : ReadOnlyDataSource(bufferSize)
{
	mFileHandle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	mLastError = mFileHandle == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
}

#define VALIDATE_HANDLE if (mFileHandle == INVALID_HANDLE_VALUE) return DataSourceError::UnableToOpen

DataSourceError ReadOnlyFile::ReadImpl(void* buffer, size_t bufferLength, size_t& read)
{
	VALIDATE_HANDLE;

	read = 0;
	DWORD bytesRead = 0;
	if (FALSE == ReadFile(mFileHandle, buffer, (DWORD)bufferLength, &bytesRead, nullptr))
	{
		mLastError = GetLastError();
		return DataSourceError::UnableToRead;
	}

	read = bytesRead;
	return DataSourceError::Ok;
}

DataSourceError ReadOnlyFile::SeekImpl(uint64_t newOffset)
{
	VALIDATE_HANDLE;

	LARGE_INTEGER newLargeIntPointer, newPointer;
	newLargeIntPointer.QuadPart = newOffset;
	if (SetFilePointerEx(mFileHandle, newLargeIntPointer, &newPointer, FILE_BEGIN) == FALSE)
		return DataSourceError::InvalidOffset;

	return DataSourceError::Ok;
}

DataSourceError ReadOnlyFile::GetSizeImpl(uint64_t& size)
{
	VALIDATE_HANDLE;

	LARGE_INTEGER largeIntSize;
	auto result = GetFileSizeEx(mFileHandle, &largeIntSize);
	if (result == FALSE)
	{
		mLastError = GetLastError();
		return DataSourceError::UnableToGetSize;
	}

	size = largeIntSize.QuadPart;
	return DataSourceError::Ok;
}
