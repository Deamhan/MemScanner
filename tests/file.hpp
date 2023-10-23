#pragma once

#include "datasource.hpp"

#include <Windows.h>

class FileException : public DataSourceException
{
public:
    FileException(DataSourceError code, DWORD lastError = ERROR_SUCCESS) : DataSourceException(code), mLastError(lastError)
    {}

    DWORD GetLastErrorCode() const noexcept { return mLastError; }

protected:
    DWORD mLastError;
};

class ReadOnlyFile : public ReadOnlyDataSource
{
public:
    ReadOnlyFile(const wchar_t* path, size_t bufferSize);
    DWORD GetLastErrorCode() { return mLastError; }

    virtual ~ReadOnlyFile()
    {
        if (mFileHandle != INVALID_HANDLE_VALUE)
            CloseHandle(mFileHandle);
    }

protected:
    virtual void ReadImpl(void* buffer, size_t bufferLength, size_t& read) override;
    virtual void SeekImpl(uint64_t newOffset) override;
    virtual void GetSizeImpl(uint64_t& size) override;

    HANDLE mFileHandle;
    DWORD mLastError;
};
