#pragma once

#include <cinttypes>
#include <type_traits>
#include <vector>

enum class DataSourceError
{
    Ok,
    Unsupported,
    UnableToOpen,
    UnableToRead,
    InvalidOffset,
    UnableToGetSize,
    UnknownError,
};

class ReadOnlyDataSource
{
public:   
    DataSourceError Seek(uint64_t newOffset);
    DataSourceError Read(void* buffer, size_t bufferLength, size_t& read);
    DataSourceError Read(uint64_t newOffset, void* buffer, size_t bufferLength, size_t& read);
    DataSourceError GetSize(uint64_t& size) { return GetSizeImpl(size); }

    virtual ~ReadOnlyDataSource() = default;

    template<class T, class = std::enable_if_t<std::is_trivial<std::decay_t<T>>::value>>
    DataSourceError Read(T& data);

protected:
    ReadOnlyDataSource(size_t bufferSize);

    virtual DataSourceError ReadImpl(void* /*buffer*/, size_t /*bufferLength*/ , size_t& read) { read = 0; return DataSourceError::Unsupported; }
    virtual DataSourceError SeekImpl(uint64_t /*newOffset*/) { return DataSourceError::Unsupported; }
    virtual DataSourceError GetSizeImpl(uint64_t& size) { size = 0;  return DataSourceError::Unsupported; }
   
private:
    const size_t mBufferSize;
    std::vector<uint8_t> mCacheBuffer;
    uint8_t* const mCacheBufferEnd;
    
    uint64_t mRealPointer;
    uint8_t* mCachePointer;

    void InvalidateCache();
    DataSourceError FillCache();
    size_t ReadCachedData(void* buffer, size_t bufferLength);
    size_t GetCachedDataSize();
    bool MoveCachePointer(uint64_t newOffset);

    ReadOnlyDataSource(const ReadOnlyDataSource&) = delete;
    ReadOnlyDataSource(ReadOnlyDataSource&&) = delete;
    ReadOnlyDataSource& operator = (const ReadOnlyDataSource&) = delete;
    ReadOnlyDataSource& operator = (ReadOnlyDataSource&&) = delete;
};

template<class T, class>
inline DataSourceError ReadOnlyDataSource::Read(T& data)
{
    size_t read;
    auto err = Read(&data, sizeof(data), read);
    if (err != DataSourceError::Ok)
        return err;

    return read == sizeof(data) ? DataSourceError::Ok : DataSourceError::UnknownError;
}
