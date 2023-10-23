#pragma once

#include "datasource.hpp"

#include "ntdll64.hpp"

class ReadOnlyMemoryDataSource : public ReadOnlyDataSource
{
public:
    ReadOnlyMemoryDataSource(HANDLE hProcess, uint64_t baseAddress, uint64_t size);

protected:
    virtual void ReadImpl(void* buffer, size_t bufferLength, size_t& read) override;
    virtual void SeekImpl(uint64_t newOffset) override;
    virtual void GetSizeImpl(uint64_t& size) override { size = mSize; }

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

    void ReadImpl(void* buffer, size_t bufferLength, size_t& read) override { ReadOnlyMemoryDataSource::ReadImpl(buffer, bufferLength, read); }
    void SeekImpl(uint64_t newOffset) override { ReadOnlyMemoryDataSource::SeekImpl(newOffset); }
    void GetSizeImpl(uint64_t& size) override { ReadOnlyMemoryDataSource::GetSizeImpl(size); }
};
