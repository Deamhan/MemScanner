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
    UnableToWrite,
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

class DataSource
{
public:   
    void Seek(uint64_t newOffset);

    size_t Read(void* buffer, size_t bufferLength);
    size_t Read(uint64_t newOffset, void* buffer, size_t bufferLength)
    {
        Seek(newOffset);
        return Read(buffer, bufferLength);
    }

    size_t Write(const void* buffer, size_t bufferLength);
    size_t Write(uint64_t newOffset, const void* buffer, size_t bufferLength)
    {
        Seek(newOffset);
        return Write(buffer, bufferLength);
    }

    uint64_t GetSize() const { return GetSizeImpl(); }

    uint64_t GetOrigin() const { return GetOriginImpl(); }

    uint64_t GetOffset() const noexcept;

    virtual ~DataSource() = default;

    template<class T, class = std::enable_if_t<std::is_trivial<std::decay_t<T>>::value>>
    void Read(T& data);

    template<class T, class = std::enable_if_t<std::is_trivial<std::decay_t<T>>::value>>
    void Read(uint64_t newOffset, T& data)
    {
        Seek(newOffset);
        Read(data);
    }

    template<class T, class = std::enable_if_t<std::is_trivial<std::decay_t<T>>::value>>
    void Write(const T& data);

    template<class T, class = std::enable_if_t<std::is_trivial<std::decay_t<T>>::value>>
    void Write(uint64_t newOffset, const T& data)
    {
        Seek(newOffset);
        Write(data);
    }

protected:
    DataSource(size_t bufferSize);

    virtual size_t ReadImpl(void* /*buffer*/, size_t /*bufferLength*/) { throw DataSourceException{DataSourceError::Unsupported}; }
    virtual size_t WriteImpl(const void* /*buffer*/, size_t /*bufferLength*/) { throw DataSourceException{ DataSourceError::Unsupported }; }
    virtual void SeekImpl(uint64_t /*newOffset*/) { throw DataSourceException { DataSourceError::Unsupported }; }
    virtual uint64_t GetSizeImpl() const { throw DataSourceException{ DataSourceError::Unsupported }; }
    virtual uint64_t GetOriginImpl() const { throw DataSourceException{ DataSourceError::Unsupported }; }
   
private:
    const size_t mBufferSize;
    std::vector<uint8_t> mCacheBuffer;
    uint8_t* const mCacheBufferEnd;
    
    uint64_t mRealPointer;
    uint8_t* mCachePointer;

    void InvalidateCache();
    void FillCache();
    size_t ReadCachedData(void* buffer, size_t bufferLength);
    size_t GetCachedDataSize() const noexcept;
    bool MoveCachePointer(uint64_t newOffset);

    DataSource(const DataSource&) = delete;
    DataSource(DataSource&&) = delete;
    DataSource& operator = (const DataSource&) = delete;
    DataSource& operator = (DataSource&&) = delete;
};

class DataSourceFragment : public DataSource
{
public:
    DataSourceFragment(DataSource& dataSource, uint64_t offset, uint64_t size);

    size_t ReadImpl(void* buffer, size_t bufferLength) override;
    void SeekImpl(uint64_t newOffset) override;
    uint64_t GetSizeImpl() const override;
    uint64_t GetOriginImpl() const override { return mOrigin + mDataSource.GetOrigin(); }

protected:
    DataSource& mDataSource;
    uint64_t mOrigin;
    uint64_t mSize;
};


template<class T, class>
inline void DataSource::Read(T& data)
{
    size_t read = Read(&data, sizeof(data));

    if (read != sizeof(data))
        throw DataSourceException{ DataSourceError::UnknownError };
}

template<class T, class>
inline void DataSource::Write(const T& data)
{
    size_t written = Write(&data, sizeof(data));

    if (written != sizeof(data))
        throw DataSourceException{ DataSourceError::UnknownError };
}

const uint32_t PAGE_SIZE = 4096;
template <class T>
inline T PageAlignUp(T value) { return (value + PAGE_SIZE - 1) & (~(PAGE_SIZE - 1)); }
