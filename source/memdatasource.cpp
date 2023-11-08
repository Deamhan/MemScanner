#include "memdatasource.hpp"

#include "file.hpp"

ReadOnlyMemoryDataSource::ReadOnlyMemoryDataSource(HANDLE hProcess, uint64_t baseAddress, uint64_t size) : DataSource(64 * 1024),
	mOffset(0), mBaseAddress(baseAddress), mSize(size), mProcess(hProcess), mApi(GetIWow64Helper())
{
	if (mProcess == nullptr)
		throw DataSourceException{ DataSourceError::InvalidHandle };
}

size_t ReadOnlyMemoryDataSource::ReadImpl(void* buffer, size_t bufferLength)
{
	auto realAddress = mOffset + mBaseAddress;
	uint64_t read64 = 0;
	if (FALSE == mApi.ReadProcessMemory64(mProcess, realAddress, buffer, bufferLength, &read64))
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

void ReadOnlyMemoryDataSource::Dump(const wchar_t* path, uint64_t begin, uint64_t size)
{
	Seek(begin);
	std::vector<uint64_t> buffer(64 * 1024);
	File dump(path, File::OpenForReadWrite, 0);

	uint64_t left = size;
	while (left != 0)
	{
		auto blockSize = (size_t)std::min<uint64_t>(buffer.size(), left);
		Read(buffer.data(), blockSize);
		dump.Write(buffer.data(), blockSize);
	}
}

ReadOnlyMemoryDataSourceEx::ReadOnlyMemoryDataSourceEx(DWORD pid, uint64_t baseAddress, uint64_t size) : 
	ReadOnlyMemoryDataSource(OpenProcess(PROCESS_VM_READ, FALSE, pid), baseAddress, size)
{}
