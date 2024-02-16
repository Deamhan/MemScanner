#include "memhelper.hpp"

int main()
{
    const auto& helper = GetIWow64Helper();
    LARGE_INTEGER creationTime = {};
    if (!helper.QueryProcessCreateionTime(GetCurrentProcess(),creationTime) || creationTime.QuadPart == 0)
        return 1;
    
    auto currentProcessName = helper.QueryProcessName(GetCurrentProcess());
    if (currentProcessName != L"query_process_test.exe")
        return 2;
    
    return 0;
}
