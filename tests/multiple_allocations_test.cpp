#include <algorithm>
#include <vector>

#include "memhelper.hpp"

static void* AllocateWithReserve()
{
	auto reservedSpace = VirtualAlloc(nullptr, 0x10000, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (reservedSpace == nullptr)
		return nullptr;

	return VirtualAlloc((char*)reservedSpace + 0x1000, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}

static bool ValidateIterators(const std::vector<void*> addresses)
{
	for (void* p : addresses)
	{
		bool isAlignedAllocation = false;
		MemoryHelperBase::MemoryMapT result;
		MemoryHelperBase::MemoryMapConstIteratorT begin, end;
		GetMemoryHelper().UpdateMemoryMapForAddr(GetCurrentProcess(), (uintptr_t)p, result, begin, end, isAlignedAllocation);

		if (std::distance(begin, end) != 3) // must be reserved - committed - reserved 
			return false;

		if (std::any_of(begin, end, [allocBase = begin->second.AllocationBase](const auto& item)
			{
				return item.second.AllocationBase != allocBase;
			}))
			return false;
	}

	return true;
}

int main()
{
	std::vector<void*> addresses;
	for (int i = 0; i < 10; ++i)
		addresses.push_back(AllocateWithReserve());

	return ValidateIterators(addresses) ? 0 : 1;
}
