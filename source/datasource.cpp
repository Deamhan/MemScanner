#include "datasource.hpp"

#include <algorithm>

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

void ReadOnlyDataSource::FillCache()
{
	InvalidateCache();

	size_t read = 0;
	ReadImpl(mCacheBuffer.data(), mCacheBuffer.size(), read);

	mRealPointer += read;
	mCachePointer = mCacheBuffer.data();
}

void ReadOnlyDataSource::Read(void* buffer, size_t bufferLength, size_t& read)
{
	read = 0;
	if (bufferLength == 0)
		return;

	read = ReadCachedData(buffer, bufferLength);
	if (read == bufferLength)
		return;

	auto byteBufferLeft = (uint8_t*)buffer + read;
	auto left = bufferLength - read;
	if (left > mBufferSize)
	{
		size_t readWithoutCache = 0;
		ReadImpl(byteBufferLeft, left, readWithoutCache);
		read += readWithoutCache;
		mRealPointer += readWithoutCache;
		InvalidateCache();

		return;
	}

	FillCache();

	read += ReadCachedData(byteBufferLeft, left);
}

void ReadOnlyDataSource::Seek(uint64_t newOffset)
{
	if (MoveCachePointer(newOffset))
		return;

	InvalidateCache();
	SeekImpl(newOffset);

	mRealPointer = newOffset;
}

#define PAGE_SIZE 4096
size_t PageAlignUp(size_t value) { return (value + PAGE_SIZE - 1) & (~(PAGE_SIZE - 1)); }

ReadOnlyDataSource::ReadOnlyDataSource(size_t bufferSize) : mBufferSize(PageAlignUp(bufferSize)), mCacheBuffer(mBufferSize),
	mRealPointer(0), mCacheBufferEnd(mCacheBuffer.data() + mCacheBuffer.size())
{
	InvalidateCache();
}
