#include "pe.hpp"

template <CPUArchitecture arch>
int CheckPE(ReadOnlyMemoryDataSource& ds, uint64_t offset)
{
	PEFile<arch> pe(ds, offset);
	return pe.IsPeValid() ? 0 : 2;
}

int main()
{
	std::vector<WCHAR> buffer(120 * 1024);
	auto selfBase = GetModuleHandleW(nullptr);
	if (selfBase == nullptr)
		return 1;

	ReadOnlyMemoryDataSource selfImageDs(GetCurrentProcess(), (uintptr_t)selfBase, 1024 * 1024);
	return PEFile<>::GetPeArch(selfImageDs, 0) == CPUArchitecture::X64 ?
		CheckPE<CPUArchitecture::X64>(selfImageDs, 0) : CheckPE<CPUArchitecture::X86>(selfImageDs, 0);
}
