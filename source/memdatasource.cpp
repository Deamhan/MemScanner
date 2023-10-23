#include "memdatasource.hpp"

ReadOnlyMemoryDataSource::ReadOnlyMemoryDataSource(HANDLE hProcess, uint64_t baseAddress, uint64_t size) : ReadOnlyDataSource(64 * 1024),
	mOffset(0), mBaseAddress(baseAddress), mSize(size), mProcess(hProcess), mApi(GetIWow64Helper())
{
	if (mProcess == nullptr)
		throw DataSourceException{ DataSourceError::InvalidHandle };
}

void ReadOnlyMemoryDataSource::ReadImpl(void* buffer, size_t bufferLength, size_t& read)
{
	auto realAddress = mOffset + mBaseAddress;
	uint64_t read64 = 0;
	if (FALSE == mApi.ReadProcessMemory64(mProcess, realAddress, buffer, bufferLength, &read64))
		throw DataSourceException{ DataSourceError::UnableToRead };

	read = (size_t)read64;
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
