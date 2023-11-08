#include "datasource.hpp"

#include <algorithm>

void DataSource::InvalidateCache()
{
	mCachePointer = mCacheBufferEnd;
}

size_t DataSource::GetCachedDataSize() const noexcept
{
	return mCacheBufferEnd - mCachePointer;
}

bool DataSource::MoveCachePointer(uint64_t newOffset)
{
	auto vCacheBeginPointer = mRealPointer - mBufferSize;
	if (newOffset >= vCacheBeginPointer && newOffset < mRealPointer)
	{
		mCachePointer = mCacheBuffer.data() + (newOffset - vCacheBeginPointer);
		return true;
	}

	return false;
}

size_t DataSource::ReadCachedData(void* buffer, size_t bufferLength)
{
	auto cachedDataSize = GetCachedDataSize();
	auto dataToCopyLen = std::min((size_t)cachedDataSize, bufferLength);

	if (dataToCopyLen == 0)
		return 0;
	
	memcpy(buffer, mCachePointer, dataToCopyLen);
	mCachePointer += dataToCopyLen;

	return dataToCopyLen;
}

void DataSource::FillCache()
{
	InvalidateCache();

	size_t read = ReadImpl(mCacheBuffer.data(), mCacheBuffer.size());

	mRealPointer += read;
	mCachePointer = mCacheBuffer.data();
}

size_t DataSource::Read(void* buffer, size_t bufferLength)
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

size_t DataSource::Write(const void* buffer, size_t bufferLength)
{
	if (GetCachedDataSize() != 0)
	{
		auto logicalOffset = GetOffset();
		SeekImpl(logicalOffset);
		InvalidateCache();

		mRealPointer = logicalOffset;
	}

	size_t written = WriteImpl(buffer, bufferLength);
	mRealPointer += written;

	return written;
}

void DataSource::Seek(uint64_t newOffset)
{
	if (MoveCachePointer(newOffset))
		return;

	InvalidateCache();
	SeekImpl(newOffset);

	mRealPointer = newOffset;
}

DataSource::DataSource(size_t bufferSize) : mBufferSize(PageAlignUp(bufferSize)), mCacheBuffer(mBufferSize),
	mRealPointer(0), mCacheBufferEnd(mCacheBuffer.data() + mCacheBuffer.size())
{
	InvalidateCache();
}

uint64_t DataSource::GetOffset() const noexcept
{
	return mRealPointer - GetCachedDataSize();
}

void DataSource::Dump(DataSource& dst, uint64_t begin, uint64_t size, size_t blockSize, bool useZeroFilling)
{
	Seek(begin);
	std::vector<uint64_t> buffer(blockSize);

	uint64_t left = size;
	while (left != 0)
	{
		auto chunkSize = (size_t)std::min<uint64_t>(buffer.size(), left);

		try
		{
			Read(buffer.data(), chunkSize);
		}
		catch (DataSourceException&)
		{
			if (!useZeroFilling)
				throw;

			memset(buffer.data(), 0, chunkSize);
		}

		dst.Write(buffer.data(), chunkSize);
		left -= chunkSize;
	}
}

DataSourceFragment::DataSourceFragment(DataSource& dataSource, uint64_t offset, uint64_t size) : 
	DataSource(0), mDataSource(dataSource), mOrigin(offset), mSize(size)
{}

size_t DataSourceFragment::ReadImpl(void* buffer, size_t bufferLength)
{
	return mDataSource.Read(buffer, bufferLength);
}

void DataSourceFragment::SeekImpl(uint64_t newOffset)
{
	return mDataSource.Seek(newOffset + mOrigin);
}

uint64_t DataSourceFragment::GetSizeImpl() const
{
	return mDataSource.GetSize() - mOrigin;
}
