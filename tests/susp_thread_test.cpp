#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "scanner.hpp"

static void CloseHandleByPtr(HANDLE* handle)
{
    CloseHandle(*handle);
}

static void FreeVirtualMemory(void* p)
{
    VirtualFree(p, 0, MEM_RELEASE);
}

static void TestThreadFunc(HANDLE hEvent)
{
    SetEvent(hEvent);
    while (true)
        Sleep(1000);
}

int main()
{
#if _M_AMD64
    const uint8_t code[] = { 0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0xFF, 0xE0 };
    const size_t offset = 2;
#else
    const uint8_t code[] = { 0xB8, 0x78, 0x56, 0x34, 0x12, 0xFF, 0xE0 };
    const size_t offset = 1;
#endif // _M_AMD64
    auto pExec = (uint8_t*)VirtualAlloc(nullptr, sizeof(code), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pExec == nullptr)
    {
        wprintf(L"!>> Unable to allocate memory <<!\n");
        return 1;
    }

    std::unique_ptr<void, void (*)(void*)> vGuad(pExec, FreeVirtualMemory);
    wprintf(L">>> Thread address = 0x%016llx <<<\n", (unsigned long long)pExec);
    memcpy(pExec, code, sizeof(code));
    *(uintptr_t*)(pExec + offset) = (uintptr_t)TestThreadFunc;
    DWORD oldProt = 0;
    VirtualProtect(pExec, sizeof(code), PAGE_EXECUTE_READ, &oldProt);

    HANDLE hEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    std::unique_ptr<HANDLE, void(*)(HANDLE*)> eventGuard(&hEvent, CloseHandleByPtr);
    HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)pExec, hEvent, 0, nullptr);
    std::unique_ptr<HANDLE, void(*)(HANDLE*)> threadGuard(&hThread, CloseHandleByPtr);
    WaitForSingleObject(hEvent, INFINITE);

    if (ScanMemory(0, GetCurrentProcessId(), L".") == 0)
    {
        wprintf(L"!>> Unable to find threat <<!\n");
        return 1;
    }
        
    FILE* dump = nullptr;
    _wfopen_s(&dump, std::to_wstring(GetCurrentProcessId()).append(L".dump").c_str(), L"rb");
    if (dump == nullptr)
    {
        wprintf(L"!>> Unable to open dump <<!\n");
        return 1;
    }    

    std::unique_ptr<FILE, int(*)(FILE*)> dumpGurad(dump, fclose);
    fseek(dump, 0, SEEK_END);
    auto size = ftell(dump);
    fseek(dump, 0, SEEK_SET);

    std::vector<uint8_t> buffer(size);
    if (fread(buffer.data(), sizeof(uint8_t), size, dump) != (size_t)size)
    {
        wprintf(L"!>> Unable to read dump <<!\n");
        return 1;
    }
        
    for (size_t i = 0; i < size - sizeof(code) + 1; ++i)
    {
        if (memcmp(&buffer[i], pExec, sizeof(code)) == 0)
        {
            wprintf(L">>> Threat signature was successfully found! <<<\n");
            return 0;
        }    
    }

    wprintf(L"!>> Unable to find the signature <<!\n");
    return 1;
}
