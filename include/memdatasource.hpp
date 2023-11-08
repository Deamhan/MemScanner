#pragma once

#include "datasource.hpp"

#include "ntdll64.hpp"

class ReadOnlyMemoryDataSource : public DataSource
{
public:
    ReadOnlyMemoryDataSource(HANDLE hProcess, uint64_t baseAddress, uint64_t size);

    void Dump(const wchar_t* path, uint64_t begin, uint64_t size);

protected:
    size_t ReadImpl(void* buffer, size_t bufferLength) override;
    void SeekImpl(uint64_t newOffset) override;
    uint64_t GetSizeImpl() const override { return mSize; }
    uint64_t GetOriginImpl() const override { return mBaseAddress; }

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
};
