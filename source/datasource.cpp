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

	size_t read = ReadImpl(mCacheBuffer.data(), mCacheBuffer.size());

	mRealPointer += read;
	mCachePointer = mCacheBuffer.data();
}

size_t ReadOnlyDataSource::Read(void* buffer, size_t bufferLength)
{
	if (bufferLength == 0)
		return 0;

	size_t read = ReadCachedData(buffer, bufferLength);
	if (read == bufferLength)
		return read;

	auto byteBufferLeft = (uint8_t*)buffer + read;
	auto left = bufferLength - read;
	if (left > mBufferSize)
	{
		size_t readWithoutCache = ReadImpl(byteBufferLeft, left);
		read += readWithoutCache;
		mRealPointer += readWithoutCache;
		InvalidateCache();

		return read;
	}

	FillCache();

	read += ReadCachedData(byteBufferLeft, left);
	return read;
}

void ReadOnlyDataSource::Seek(uint64_t newOffset)
{
	if (MoveCachePointer(newOffset))
		return;

	InvalidateCache();
	SeekImpl(newOffset);

	mRealPointer = newOffset;
}

ReadOnlyDataSource::ReadOnlyDataSource(size_t bufferSize) : mBufferSize(PageAlignUp(bufferSize)), mCacheBuffer(mBufferSize),
	mRealPointer(0), mCacheBufferEnd(mCacheBuffer.data() + mCacheBuffer.size())
{
	InvalidateCache();
}

DataSourceFragment::DataSourceFragment(ReadOnlyDataSource& dataSource, uint64_t offset, uint64_t size) : 
	ReadOnlyDataSource(0), mDataSource(dataSource), mOffset(offset), mSize(size)
{}

size_t DataSourceFragment::ReadImpl(void* buffer, size_t bufferLength)
{
	return mDataSource.Read(buffer, bufferLength);
}

void DataSourceFragment::SeekImpl(uint64_t newOffset)
{
	return mDataSource.Seek(newOffset + mOffset);
}

uint64_t DataSourceFragment::GetSizeImpl() const
{
	return mDataSource.GetSize() - mOffset;
}
