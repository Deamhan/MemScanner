#include "memdatasource.hpp"

ReadOnlyMemoryDataSource::ReadOnlyMemoryDataSource(HANDLE hProcess, uint64_t baseAddress, uint64_t size, size_t bufferSize) 
	: DataSource(bufferSize), mOffset(0), mBaseAddress(baseAddress), mSize(size), mProcess(hProcess), mApi(GetIWow64Helper())
{
	if (mProcess == nullptr)
		throw DataSourceException{ DataSourceError::InvalidHandle };
}

size_t ReadOnlyMemoryDataSource::ReadImpl(void* buffer, size_t bufferLength)
{
	auto realAddress = mOffset + mBaseAddress;
	uint64_t read64 = 0;
	if (!mApi.ReadProcessMemory64(mProcess, realAddress, buffer, bufferLength, &read64))
		throw DataSourceException{ DataSourceError::UnableToRead };

	mOffset += read64;
	return (size_t)read64;
}

void ReadOnlyMemoryDataSource::SeekImpl(uint64_t newOffset)
{
	if (newOffset > mSize)
		throw DataSourceException{ DataSourceError::InvalidOffset };

	mOffset = newOffset;
}

ReadOnlyMemoryDataSourceEx::ReadOnlyMemoryDataSourceEx(DWORD pid, uint64_t baseAddress, uint64_t size) : 
	ReadOnlyMemoryDataSource(OpenProcess(PROCESS_VM_READ, FALSE, pid), baseAddress, size)
{}
