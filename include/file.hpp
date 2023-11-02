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
    ReadOnlyFile(const wchar_t* path, size_t bufferSize = 64 * 1024);
    DWORD GetLastErrorCode() { return mLastError; }

    virtual ~ReadOnlyFile()
    {
        if (mFileHandle != INVALID_HANDLE_VALUE)
            CloseHandle(mFileHandle);
    }

protected:
    size_t ReadImpl(void* buffer, size_t bufferLength) override;
    void SeekImpl(uint64_t newOffset) override;
    uint64_t GetSizeImpl() const override;
    uint64_t GetOffsetImpl() const override { return 0; }

    HANDLE mFileHandle;
    DWORD mLastError;
};
