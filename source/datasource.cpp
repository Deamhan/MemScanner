#include "datasource.hpp"

#include <algorithm>

DataSourceError ReadOnlyDataSource::Read(uint64_t newOffset, void* buffer, size_t bufferLength, size_t& read)
{
	auto err = Seek(newOffset);
	if (err != DataSourceError::Ok)
		return err;

	return Read(buffer, bufferLength, read);
}

void ReadOnlyDataSource::InvalidateCache()
{
	mCachePointer = mCacheBufferEnd;
}

size_t ReadOnlyDataSource::GetCachedDataSize()
{
	return mCacheBufferEnd - mCachePointer;
}

bool ReadOnlyDataSource::MoveCachePointer(uint64_t newOffset)
{
	auto vCacheBeginPointer = mRealPointer - mBufferSize;
	if (newOffset >= vCacheBeginPointer && newOffset < mRealPointer)
	{
		mCachePointer = mCacheBuffer.data() + (newOffset - vCacheBeginPointer);
		return true;
	}

	return false;
}

size_t ReadOnlyDataSource::ReadCachedData(void* buffer, size_t bufferLength)
{
	auto cachedDataSize = GetCachedDataSize();
	auto dataToCopyLen = std::min((size_t)cachedDataSize, bufferLength);

	if (dataToCopyLen == 0)
		return 0;
	
	memcpy(buffer, mCachePointer, dataToCopyLen);
	mCachePointer += dataToCopyLen;

	return dataToCopyLen;
}

DataSourceError ReadOnlyDataSource::FillCache()
{
	InvalidateCache();

	size_t read = 0;
	auto error = ReadImpl(mCacheBuffer.data(), mCacheBuffer.size(), read);
	if (error != DataSourceError::Ok)
		return error;

	mRealPointer += read;
	mCachePointer = mCacheBuffer.data();

	return DataSourceError::Ok;
}

DataSourceError ReadOnlyDataSource::Read(void* buffer, size_t bufferLength, size_t& read)
{
	read = 0;
	if (bufferLength == 0)
		return DataSourceError::Ok;

	read = ReadCachedData(buffer, bufferLength);
	if (read == bufferLength)
		return DataSourceError::Ok;

	auto byteBufferLeft = (uint8_t*)buffer + read;
	auto left = bufferLength - read;
	if (left > mBufferSize)
	{
		size_t readWithoutCache = 0;
		auto result = ReadImpl(byteBufferLeft, left, readWithoutCache);
		read += readWithoutCache;
		mRealPointer += readWithoutCache;
		InvalidateCache();

		return result;
	}

	auto error = FillCache();
	if (error != DataSourceError::Ok)
		return error;

	read += ReadCachedData(byteBufferLeft, left);
	return DataSourceError::Ok;
}

DataSourceError ReadOnlyDataSource::Seek(uint64_t newOffset)
{
	if (MoveCachePointer(newOffset))
		return DataSourceError::Ok;

	InvalidateCache();
	auto error = SeekImpl(newOffset);
	if (error != DataSourceError::Ok)
		return error;

	mRealPointer = newOffset;
	return DataSourceError::Ok;
}

#define PAGE_SIZE 4096
size_t PageAlignUp(size_t value) { return (value + PAGE_SIZE - 1) & (~(PAGE_SIZE - 1)); }

ReadOnlyDataSource::ReadOnlyDataSource(size_t bufferSize) : mBufferSize(PageAlignUp(bufferSize)), mCacheBuffer(mBufferSize),
	mRealPointer(0), mCacheBufferEnd(mCacheBuffer.data() + mCacheBuffer.size())
{
	InvalidateCache();
}
