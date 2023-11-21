#include "memdatasource.hpp"

int main()
{
	auto reserved = (char*)VirtualAlloc(nullptr, 2 * 4096, MEM_RESERVE, PAGE_READWRITE);
	auto committed = VirtualAlloc(reserved + 4096, 4096, MEM_COMMIT, PAGE_READWRITE);
	memset(committed, 0xc0, 4096);
	ReadOnlyMemoryDataSource ds(GetCurrentProcess(), (uintptr_t)committed, 4096);

	try
	{
		uint32_t tmp = 0;
		ds.Read(3072, tmp);

		return tmp == 0xc0c0c0c0 ? 0 : 2;
	}
	catch (const DataSourceException&)
	{
		return 1;
	}
}
