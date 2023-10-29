#pragma once

#include <cinttypes>
#include <exception>
#include <type_traits>
#include <vector>

enum class DataSourceError
{
    Unsupported,
    UnableToOpen,
    UnableToRead,
    InvalidOffset,
    InvalidHandle,
    UnableToGetSize,
    UnknownError,
};

class DataSourceException : public std::exception
{
public:
    DataSourceException(DataSourceError code) : mErrorCode(code)
    {}
    
    DataSourceError GetErrorCode() const noexcept { return mErrorCode; }

protected:
    DataSourceError mErrorCode;
};

class ReadOnlyDataSource
{
public:   
    void Seek(uint64_t newOffset);
    size_t Read(void* buffer, size_t bufferLength);
    size_t Read(uint64_t newOffset, void* buffer, size_t bufferLength)
    {
        Seek(newOffset);
        return Read(buffer, bufferLength);
    }
    uint64_t GetSize() { return GetSizeImpl(); }

    virtual ~ReadOnlyDataSource() = default;

    template<class T, class = std::enable_if_t<std::is_trivial<std::decay_t<T>>::value>>
    void Read(T& data);

    template<class T, class = std::enable_if_t<std::is_trivial<std::decay_t<T>>::value>>
    void Read(uint64_t newOffset, T& data)
    {
        Seek(newOffset);
        Read(data);
    }

protected:
    ReadOnlyDataSource(size_t bufferSize);

    virtual size_t ReadImpl(void* /*buffer*/, size_t /*bufferLength*/) { throw DataSourceException{DataSourceError::Unsupported}; }
    virtual void SeekImpl(uint64_t /*newOffset*/) { throw DataSourceException { DataSourceError::Unsupported }; }
    virtual uint64_t GetSizeImpl() { throw DataSourceException{ DataSourceError::Unsupported }; }
   
private:
    const size_t mBufferSize;
    std::vector<uint8_t> mCacheBuffer;
    uint8_t* const mCacheBufferEnd;
    
    uint64_t mRealPointer;
    uint8_t* mCachePointer;

    void InvalidateCache();
    void FillCache();
    size_t ReadCachedData(void* buffer, size_t bufferLength);
    size_t GetCachedDataSize();
    bool MoveCachePointer(uint64_t newOffset);

    ReadOnlyDataSource(const ReadOnlyDataSource&) = delete;
    ReadOnlyDataSource(ReadOnlyDataSource&&) = delete;
    ReadOnlyDataSource& operator = (const ReadOnlyDataSource&) = delete;
    ReadOnlyDataSource& operator = (ReadOnlyDataSource&&) = delete;
};

class DataSourceFragment : public ReadOnlyDataSource
{
public:
    DataSourceFragment(ReadOnlyDataSource& dataSource, uint64_t offset, uint64_t size);

    size_t ReadImpl(void* buffer, size_t bufferLength) override;
    void SeekImpl(uint64_t newOffset) override;
    uint64_t GetSizeImpl() override;

protected:
    ReadOnlyDataSource& mDataSource;
    uint64_t mOffset;
    uint64_t mSize;
};


template<class T, class>
inline void ReadOnlyDataSource::Read(T& data)
{
    size_t read = Read(&data, sizeof(data));

    if (read != sizeof(data))
        throw DataSourceException{ DataSourceError::UnknownError };
}

#define PAGE_SIZE 4096
inline size_t PageAlignUp(size_t value) { return (value + PAGE_SIZE - 1) & (~(PAGE_SIZE - 1)); }
