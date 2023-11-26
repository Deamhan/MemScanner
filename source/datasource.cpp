#include "datasource.hpp"

#include <algorithm>

#include <memhelper.hpp>

#undef min
#undef max

void DataSource::ReinitCache(size_t newSize)
{
	mCacheBuffer.resize(newSize);
	mCurrentCacheOffset = 0;
}

size_t DataSource::GetCachedDataSize() const noexcept
{
	return mCacheBuffer.size() - mCurrentCacheOffset;
}

bool DataSource::MoveCachePointer(uint64_t newOffset)
{
	if (mCacheBuffer.empty())
		return false;

	auto vCacheBeginPointer = mRealPointer - mCacheBuffer.size();
	if (newOffset >= vCacheBeginPointer && newOffset < mRealPointer)
	{
		mCurrentCacheOffset = (size_t)(newOffset - vCacheBeginPointer);
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
	
	memcpy(buffer, &mCacheBuffer[mCurrentCacheOffset], dataToCopyLen);
	mCurrentCacheOffset += dataToCopyLen;

	return dataToCopyLen;
}

bool DataSource::FillCache()
{
	try
	{
		auto dataTotalSize = GetSizeImpl();
		ReinitCache((size_t)std::min<uint64_t>(dataTotalSize - mRealPointer, mBufferMaxSize));
		if (mCacheBuffer.empty())
			return true; // EOF reached

		size_t read = ReadImpl(mCacheBuffer.data(), mCacheBuffer.size());
		mRealPointer += read;
		ReinitCache(read);

		return true;
	}
	catch (const DataSourceException&)
	{
		ReinitCache(); // invalidate cache on error	
		mBufferMaxSize = 0; // disable caching, DS is not continiously readable
	}

	return false;
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

	do
	{
		if (left > mBufferMaxSize)
		{
			ReinitCache();
			size_t readWithoutCache = ReadImpl(byteBufferLeft, left);
			read += readWithoutCache;
			mRealPointer += readWithoutCache;

			return read;
		}

		if (FillCache())
			break;

	} while (true);


	read += ReadCachedData(byteBufferLeft, left);
	return read;
}

size_t DataSource::Write(const void* buffer, size_t bufferLength)
{
	if (GetCachedDataSize() != 0)
	{
		auto logicalOffset = GetOffset();
		SeekImpl(logicalOffset);
		ReinitCache();

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

	ReinitCache();
	SeekImpl(newOffset);

	mRealPointer = newOffset;
}

DataSource::DataSource(size_t bufferSize) : mBufferMaxSize(PageAlignUp(bufferSize)), mCacheBuffer(0), 
	mCurrentCacheOffset(0), mRealPointer(0)
{}

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
{
	if (mSize != 0)
		return;

	auto realDsSize = mDataSource.GetSize();
	if (realDsSize > offset)
		mSize = realDsSize - offset;
}

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
