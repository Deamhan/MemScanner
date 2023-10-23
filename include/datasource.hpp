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
    void Read(void* buffer, size_t bufferLength, size_t& read);
    void Read(uint64_t newOffset, void* buffer, size_t bufferLength, size_t& read)
    {
        Seek(newOffset);
        Read(buffer, bufferLength, read);
    }
    void GetSize(uint64_t& size) { return GetSizeImpl(size); }

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

    virtual void ReadImpl(void* /*buffer*/, size_t /*bufferLength*/ , size_t& /*read*/ ) { throw DataSourceException{DataSourceError::Unsupported}; }
    virtual void SeekImpl(uint64_t /*newOffset*/) { throw DataSourceException { DataSourceError::Unsupported }; }
    virtual void GetSizeImpl(uint64_t& /*size*/ ) { throw DataSourceException{ DataSourceError::Unsupported }; }
   
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

template<class T, class>
inline void ReadOnlyDataSource::Read(T& data)
{
    size_t read = 0;
    Read(&data, sizeof(data), read);

    if (read != sizeof(data))
        throw DataSourceException{ DataSourceError::UnknownError };
}
