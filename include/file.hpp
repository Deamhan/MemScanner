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

class File : public DataSource
{
public:
    File(const wchar_t* path, bool readOnly = true, size_t bufferSize = 64 * 1024);
    DWORD GetLastErrorCode() { return mLastError; }

    virtual ~File()
    {
        if (mFileHandle != INVALID_HANDLE_VALUE)
            CloseHandle(mFileHandle);
    }

protected:
    size_t ReadImpl(void* buffer, size_t bufferLength) override;
    size_t WriteImpl(const void* buffer, size_t bufferLength) override;
    void SeekImpl(uint64_t newOffset) override;
    uint64_t GetSizeImpl() const override;
    uint64_t GetOffsetImpl() const override { return 0; }

    HANDLE mFileHandle;
    DWORD mLastError;
};
