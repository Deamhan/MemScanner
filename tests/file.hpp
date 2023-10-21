#pragma once

#include "datasource.hpp"

#include <Windows.h>

class ReadOnlyFile : public ReadOnlyDataSource
{
public:
    ReadOnlyFile(const wchar_t* path, size_t bufferSize);
    DWORD GetLastErrorCode();

    virtual ~ReadOnlyFile()
    {
        if (mFileHandle != INVALID_HANDLE_VALUE)
            CloseHandle(mFileHandle);
    }

protected:
    virtual DataSourceError ReadImpl(void* buffer, size_t bufferLength, size_t& read) override;
    virtual DataSourceError SeekImpl(uint64_t newOffset) override;
    virtual DataSourceError GetSizeImpl(uint64_t& size) override;

    HANDLE mFileHandle;
    DWORD mLastError;
};
