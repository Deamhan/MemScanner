#include "memdatasource.hpp"

int main()
{
	std::vector<WCHAR> buffer(120 * 1024);
	auto selfBase = GetModuleHandleW(nullptr);
	if (selfBase == nullptr)
		return 1;

	ReadOnlyMemoryDataSource bufferedFile(GetCurrentProcess(), (uintptr_t)selfBase, 1024 * 1024);
	IMAGE_DOS_HEADER dosHeader;
	size_t read = 0;
	auto err = bufferedFile.Read(&dosHeader, sizeof(dosHeader), read);
	if (err != DataSourceError::Ok)
		return 2;

	if (dosHeader.e_magic != 0x5a4d)
		return 3;

	return 0;
}
