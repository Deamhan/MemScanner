#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <memory>

#include "scanner.h"

static void CloseHandleByPtr(HANDLE* handle)
{
    CloseHandle(*handle);
}

static void TestThreadFunc(HANDLE hEvent)
{
    SetEvent(hEvent);
    while (true)
        Sleep(1000);
}

int main(int argc, const char** argv)
{
    const uint8_t code[] = { 0xB8, 0x78, 0x56, 0x34, 0x12, 0xFF, 0xE0 };
    auto pExec = (uint8_t*)VirtualAlloc(nullptr, sizeof(code), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pExec == nullptr)
    {
        wprintf(L"!>> Unable to allocate memory <<!\n");
        return 1;
    }

    wprintf(L">>> Thread address = 0x%016llx <<<\n", (unsigned long long)pExec);
    memcpy(pExec, code, sizeof(code));
    *(uint32_t*)(pExec + 1) = (uint32_t)TestThreadFunc;
    DWORD oldProt = 0;
    VirtualProtect(pExec, sizeof(code), PAGE_EXECUTE_READ, &oldProt);

    HANDLE hEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    std::unique_ptr<HANDLE, void(*)(HANDLE*)> eventGuard(&hEvent, CloseHandleByPtr);
    HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)pExec, hEvent, 0, nullptr);
    std::unique_ptr<HANDLE, void(*)(HANDLE*)> threadGuard(&hThread, CloseHandleByPtr);
    WaitForSingleObject(hEvent, INFINITE);

    auto result = ScanMemory();

    return result != 0 ? 0 : 1;
}