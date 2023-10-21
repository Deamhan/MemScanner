#include "file.hpp"

#include <utility>
#include <vector>

int CompareData(ReadOnlyFile& bufferedFile, ReadOnlyFile& unbufferedFile, uint64_t offset, size_t size)
{
	std::vector<uint8_t> buffer1(size), buffer2(size);
	ReadOnlyFile* dsArray[2] = { &bufferedFile,  &unbufferedFile };
	std::vector<uint8_t>* bufferArray[2] = { &buffer1,  &buffer2 };

	for (size_t i = 0; i < _countof(dsArray); ++i)
	{
		auto& ds = *dsArray[i];
		auto err = ds.Seek(offset);
		if (err != DataSourceError::Ok)
			return 11;

		auto& buffer = *bufferArray[i];
		size_t read = 0;
		err = ds.Read(buffer.data(), size, read);
		if (err != DataSourceError::Ok)
			return 12;
	}

	if (memcmp(buffer1.data(), buffer2.data(), size) != 0)
		return 13;

	return 0;
}

int main()
{
	std::vector<WCHAR> buffer(32 * 1024);
	DWORD len = GetModuleFileNameW(nullptr, buffer.data(), (DWORD)buffer.size());
	if (len == 0)
		return 1;

	ReadOnlyFile bufferedFile(buffer.data(), 4096), unbufferedFile(buffer.data(), 0);
	if (bufferedFile.GetLastErrorCode() != ERROR_SUCCESS || unbufferedFile.GetLastErrorCode() != ERROR_SUCCESS)
		return 2;

	
	std::vector<std::pair<uint64_t, size_t>> offsetsAndSizes = { {0, 5}, {128, 100}, {10, 25}, { 8192, 8192 }, {20, 100}, { 120, 4 * 4096}, {0, 10}, {3, 8096} };
	for (auto& kv : offsetsAndSizes)
	{
		auto res = CompareData(bufferedFile, unbufferedFile, kv.first, kv.second);
		if (res != 0)
			return res;
	}

	return 0;
}