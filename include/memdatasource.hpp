#pragma once

#include "datasource.hpp"

#include "ntdll64.hpp"

class ReadOnlyMemoryDataSource : public ReadOnlyDataSource
{
public:
    ReadOnlyMemoryDataSource(HANDLE hProcess, uint64_t baseAddress, uint64_t size);

protected:
    virtual DataSourceError ReadImpl(void* buffer, size_t bufferLength, size_t& read) override;
    virtual DataSourceError SeekImpl(uint64_t newOffset) override;
    virtual DataSourceError GetSizeImpl(uint64_t& size) override { size = mSize; return DataSourceError::Ok; }

    uint64_t  mBaseAddress;
    uint64_t  mSize;
    uint64_t  mOffset;
    HANDLE    mProcess;

    const IWow64Helper& mApi;
};

class ReadOnlyMemoryDataSourceEx : protected ReadOnlyMemoryDataSource
{
public:
    ReadOnlyMemoryDataSourceEx(DWORD pid, uint64_t baseAddress, uint64_t size);

    ~ReadOnlyMemoryDataSourceEx()
    {
        if (mProcess != nullptr)
            CloseHandle(mProcess);
    }

    DataSourceError ReadImpl(void* buffer, size_t bufferLength, size_t& read) override { return ReadOnlyMemoryDataSource::ReadImpl(buffer, bufferLength, read); }
    DataSourceError SeekImpl(uint64_t newOffset) override { return ReadOnlyMemoryDataSource::SeekImpl(newOffset); }
    DataSourceError GetSizeImpl(uint64_t& size) override { return ReadOnlyMemoryDataSource::GetSizeImpl(size); }
};
