#pragma once

#include <cinttypes>
#include <windows.h>

#pragma pack(push, 1)

namespace SystemDefinitions
{
    enum class NT_STATUS : uint32_t
    {
        StatusInfoLengthMismatch = 0xC0000004,
        StatusBufferOverflow     = 0x80000005,
        StatusBufferTooSmall     = 0xC0000023,
        StatusSuccess            = 0x00000000,
    };

    enum class SYSTEM_INFORMATION_CLASS : uint32_t 
    {
        SystemBasicInformation,
        SystemProcessorInformation,
        SystemPerformanceInformation,
        SystemTimeOfDayInformation,
        SystemPathInformation,
        SystemProcessInformation,
        SystemCallCountInformation,
        SystemDeviceInformation,
        SystemProcessorPerformanceInformation,
        SystemFlagsInformation,
        SystemCallTimeInformation,
        SystemModuleInformation,
        SystemLocksInformation,
        SystemStackTraceInformation,
        SystemPagedPoolInformation,
        SystemNonPagedPoolInformation,
        SystemHandleInformation,
        SystemObjectInformation,
        SystemPageFileInformation,
        SystemVdmInstemulInformation,
        SystemVdmBopInformation,
        SystemFileCacheInformation,
        SystemPoolTagInformation,
        SystemInterruptInformation,
        SystemDpcBehaviorInformation,
        SystemFullMemoryInformation,
        SystemLoadGdiDriverInformation,
        SystemUnloadGdiDriverInformation,
        SystemTimeAdjustmentInformation,
        SystemSummaryMemoryInformation,
        SystemNextEventIdInformation,
        SystemEventIdsInformation,
        SystemCrashDumpInformation,
        SystemExceptionInformation,
        SystemCrashDumpStateInformation,
        SystemKernelDebuggerInformation,
        SystemContextSwitchInformation,
        SystemRegistryQuotaInformation,
        SystemExtendServiceTableInformation,
        SystemPrioritySeperation,
        SystemPlugPlayBusInformation,
        SystemDockInformation,
        SystemPowerInformation,
        SystemProcessorSpeedInformation,
        SystemCurrentTimeZoneInformation,
        SystemLookasideInformation
    };

    enum class PROCESSINFOCLASS : uint32_t
    {
        ProcessBasicInformation,
        ProcessQuotaLimits,
        ProcessIoCounters,
        ProcessVmCounters,
        ProcessTimes,
        ProcessBasePriority,
        ProcessRaisePriority,
        ProcessDebugPort,
        ProcessExceptionPort,
        ProcessAccessToken,
        ProcessLdtInformation,
        ProcessLdtSize,
        ProcessDefaultHardErrorMode,
        ProcessIoPortHandlers,
        ProcessPooledUsageAndLimits,
        ProcessWorkingSetWatch,
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup,
        ProcessPriorityClass,
        ProcessWx86Information,
        ProcessHandleCount,
        ProcessAffinityMask,
        ProcessPriorityBoost,
        ProcessDeviceMap,
        ProcessSessionInformation,
        ProcessForegroundInformation,
        ProcessWow64Information,
        ProcessImageFileName,
        ProcessLUIDDeviceMapsEnabled,
        ProcessBreakOnTermination,
        ProcessDebugObjectHandle,
        ProcessDebugFlags,
        ProcessHandleTracing,
        ProcessIoPriority,
        ProcessExecuteFlags,
        ProcessResourceManagement,
        ProcessCookie,
        ProcessImageInformation,
        MaxProcessInfoClass
    }; 

    enum class THREADINFOCLASS : uint32_t
    {
        ThreadBasicInformation,
        ThreadTimes,
        ThreadPriority,
        ThreadBasePriority, 
        ThreadAffinityMask,
        ThreadImpersonationToken,
        ThreadDescriptorTableEntry,
        ThreadEnableAlignmentFaultFixup,
        ThreadEventPair,
        ThreadQuerySetWin32StartAddress,
        ThreadZeroTlsCell,
        ThreadPerformanceCount,
        ThreadAmILastThread,
        MaxThreadInfoClass
    };

    enum class MEMORY_INFORMATION_CLASS : uint32_t
    {
        MemoryBasicInformation,
        MemoryWorkingSetList,
        MemorySectionName,
        MemoryBasicVlmInformation,
        MemoryWorkingSetExList
    };

    template <class T>
    struct UNICODE_STRING_T
    {
        union
        {
            struct
            {
                WORD Length;
                WORD MaximumLength;
            };
            T dummy;
        };
        T Buffer;
    };

    template <class T>
    struct CLIENT_ID_T
    {
        union
        {
            HANDLE UniqueProcess;
            T      UniqueProcess64;
        };
        union
        {
            HANDLE UniqueThread;
            T      UniqueThread64;
        };
    };

    typedef ULONG_PTR  KAFFINITY;
    typedef LONG       KPRIORITY;

    template <class T>
    struct THREAD_BASIC_INFORMATION_T 
    {
        union {
            NT_STATUS ExitStatus;
            T         dummy0;
        };
        union {
            PVOID     TebBaseAddress;
            T         dummy1;
        };
        CLIENT_ID_T<T> ClientId;
        union {
            KAFFINITY AffinityMask;
            T         dummy3;
        };
        union {
            KPRIORITY Priority;
            T         dummy4;
        };
        union {
            KPRIORITY BasePriority;
            T         dummy5;
        };
    };

    inline bool NtSuccess(NT_STATUS x) { return (int32_t)x >= 0; }

    inline bool IsBufferTooSmall(NT_STATUS status)
    {
        return (status == NT_STATUS::StatusBufferOverflow) || (status == NT_STATUS::StatusBufferTooSmall) || (status == NT_STATUS::StatusInfoLengthMismatch);
    }

    template <class T>
    struct VM_COUNTERS_T
    {
        T PeakVirtualSize;
        T VirtualSize;
        T PageFaultCount;
        T PeakWorkingSetSize;
        T WorkingSetSize;
        T QuotaPeakPagedPoolUsage;
        T QuotaPagedPoolUsage;
        T QuotaPeakNonPagedPoolUsage;
        T QuotaNonPagedPoolUsage;
        T PagefileUsage;
        T PeakPagefileUsage;
        T PrivatePageCount;
    };

    struct IO_COUNTERS_T 
    {
        uint64_t ReadOperationCount;
        uint64_t WriteOperationCount;
        uint64_t OtherOperationCount;
        uint64_t ReadTransferCount;
        uint64_t WriteTransferCount;
        uint64_t OtherTransferCount;
    };

    enum THREAD_STATE
    {
        StateInitialized,
        StateReady,
        StateRunning,
        StateStandby,
        StateTerminated,
        StateWait,
        StateTransition,
        StateUnknown
    };

    template <class T>
    struct SYSTEM_THREAD_T
    {
        LARGE_INTEGER  KernelTime;
        LARGE_INTEGER  UserTime;
        LARGE_INTEGER  CreateTime;
        T              WaitTime;
        T              StartAddress;
        CLIENT_ID_T<T> ClientId;
        uint32_t       Priority;
        uint32_t       BasePriority;
        uint32_t       ContextSwitchCount;
        THREAD_STATE   State;
        uint32_t       WaitReason;
        uint32_t       Reserved;
    };

    template <class T>
    struct SYSTEM_PROCESS_INFORMATION_T
    {
        uint32_t NextEntryOffset;
        uint32_t NumberOfThreads;
        LARGE_INTEGER Reserved[3];
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING_T<T> ImageName;
        T BasePriority64;
        union {
            HANDLE ProcessId;
            T      ProcessId64;
        };
        union {
            HANDLE InheritedFromProcessId;
            T      InheritedFromProcessId64;
        };
        T HandleCount;
        uint32_t  Reserved2[2];
        VM_COUNTERS_T<T>   VmCounters;
        IO_COUNTERS_T      IoCounters;
        SYSTEM_THREAD_T<T> Threads[1];
    };

    enum class MemType : uint32_t
    {
        Private = 0x00020000,
        Mapped = 0x00040000,
        Image = 0x01000000
    };

#pragma warning(push)
#pragma warning(disable:4324)
    template <class T>
    struct alignas(16) MEMORY_BASIC_INFORMATION_T
    {
        T BaseAddress;
        T AllocationBase;
        union
        {
            uint32_t AllocationProtect;
            T dummy1;
        };
        T RegionSize;
        uint32_t State;
        uint32_t Protect;
        union
        {
            MemType Type;
            T dummy2;
        };
    };
#pragma warning(pop)

    template<class T>
    struct RTL_USER_PROCESS_PARAMETERS 
    {

        ULONG MaximumLength;
        ULONG Length;
        ULONG Flags;
        ULONG DebugFlags;
        union{
            PVOID ConsoleHandle;
            T     ConsoleHandleT;
        };
        union{
            ULONG ConsoleFlags;
            T     ConsoleFlagsT;
        };
        union{
            struct{
                HANDLE StdInputHandle;
                HANDLE StdOutputHandle;
                HANDLE StdErrorHandle;
            };
            T   LongStdHandles[3];
        };
        UNICODE_STRING_T<T> CurrentDirectoryPath;
        union{
            HANDLE CurrentDirectoryHandle;
            T      CurrentDirectoryHandleT;
        };
        UNICODE_STRING_T<T> DllPath;
        UNICODE_STRING_T<T> ImagePathName;
        UNICODE_STRING_T<T> CommandLine;
        union{
            PVOID Environment;
            T     EnvironmentT;
        };
        ULONG StartingPositionLeft;
        ULONG StartingPositionTop;
        ULONG Width;
        ULONG Height;
        ULONG CharWidth;
        ULONG CharHeight;
        ULONG ConsoleTextAttributes;
        ULONG WindowFlags;
        ULONG ShowWindowFlags;
        UNICODE_STRING_T<T> WindowTitle;
        UNICODE_STRING_T<T> DesktopName;
        UNICODE_STRING_T<T> ShellInfo;
        UNICODE_STRING_T<T> RuntimeData;
    };

    template <class T>
    struct LIST_ENTRY_T
    {
        T Flink;
        T Blink;
    };

    template <class T>
    struct NT_TIB_T
    {
        T ExceptionList;
        T StackBase;
        T StackLimit;
        T SubSystemTib;
        T FiberData;
        T ArbitraryUserPointer;
        T Self;
    };

    template <class T>
    struct CLIENT_ID
    {
        T UniqueProcess;
        T UniqueThread;
    };

    template <class T>
    struct TEB_T
    {
        NT_TIB_T<T> NtTib;
        T EnvironmentPointer;
        CLIENT_ID<T> ClientId;
        T ActiveRpcHandle;
        T ThreadLocalStoragePointer;
        T ProcessEnvironmentBlock;
        DWORD LastErrorValue;
        DWORD CountOfOwnedCriticalSections;
        T CsrClientThread;
        T Win32ThreadInfo;
    };

    template <class T>
    struct LDR_DATA_TABLE_ENTRY_T
    {
        LIST_ENTRY_T<T> InLoadOrderLinks;
        LIST_ENTRY_T<T> InMemoryOrderLinks;
        LIST_ENTRY_T<T> InInitializationOrderLinks;
        T DllBase;
        T EntryPoint;
        union
        {
            DWORD SizeOfImage;
            T dummy1;
        };
        UNICODE_STRING_T<T> FullDllName;
        UNICODE_STRING_T<T> BaseDllName;
        DWORD Flags;
        WORD LoadCount;
        WORD TlsIndex;
        union
        {
            LIST_ENTRY_T<T> HashLinks;
            struct
            {
                T SectionPointer;
                T CheckSum;
            };
        };
        union
        {
            T LoadedImports;
            DWORD TimeDateStamp;
        };
        T EntryPointActivationContext;
        T PatchInformation;
        LIST_ENTRY_T<T> ForwarderLinks;
        LIST_ENTRY_T<T> ServiceTagLinks;
        LIST_ENTRY_T<T> StaticLinks;
        T ContextInformation;
        T OriginalBase;
        LARGE_INTEGER LoadTime;
    };

    template <class T>
    struct PEB_LDR_DATA_T
    {
        DWORD Length;
        DWORD Initialized;
        T SsHandle;
        LIST_ENTRY_T<T> InLoadOrderModuleList;
        LIST_ENTRY_T<T> InMemoryOrderModuleList;
        LIST_ENTRY_T<T> InInitializationOrderModuleList;
        T EntryInProgress;
        DWORD ShutdownInProgress;
        T ShutdownThreadId;
    };

    template <class T>
    struct peb_traits
    {
        typedef uint32_t T;
        typedef uint64_t NGF;
        static const int A = 34;
    };

    template<>
    struct peb_traits<uint64_t>
    {
        typedef uint64_t T;
        typedef uint32_t NGF;
        static const int A = 30;
    };

    template <class PTR_TYPE>
    struct PEB_T
    {
        typedef typename peb_traits<PTR_TYPE>::T   T;
        typedef typename peb_traits<PTR_TYPE>::NGF NGF;
        union
        {
            struct
            {
                BYTE InheritedAddressSpace;
                BYTE ReadImageFileExecOptions;
                BYTE BeingDebugged;
                BYTE BitField;
            };
            T dummy1;
        };
        T Mutant;
        T ImageBaseAddress;
        T Ldr;
        T ProcessParameters;
        T SubSystemData;
        T ProcessHeap;
        T FastPebLock;
        T AtlThunkSListPtr;
        T IFEOKey;
        T CrossProcessFlags;
        T UserSharedInfoPtr;
        DWORD SystemReserved;
        DWORD AtlThunkSListPtr32;
        T ApiSetMap;
        T TlsExpansionCounter;
        T TlsBitmap;
        DWORD TlsBitmapBits[2];
        T ReadOnlySharedMemoryBase;
        T HotpatchInformation;
        T ReadOnlyStaticServerData;
        T AnsiCodePageData;
        T OemCodePageData;
        T UnicodeCaseTableData;
        DWORD NumberOfProcessors;
        union
        {
            DWORD NtGlobalFlag;
            NGF dummy2;
        };
        LARGE_INTEGER CriticalSectionTimeout;
        T HeapSegmentReserve;
        T HeapSegmentCommit;
        T HeapDeCommitTotalFreeThreshold;
        T HeapDeCommitFreeBlockThreshold;
        DWORD NumberOfHeaps;
        DWORD MaximumNumberOfHeaps;
        T ProcessHeaps;
        T GdiSharedHandleTable;
        T ProcessStarterHelper;
        T GdiDCAttributeList;
        T LoaderLock;
        DWORD OSMajorVersion;
        DWORD OSMinorVersion;
        WORD OSBuildNumber;
        WORD OSCSDVersion;
        DWORD OSPlatformId;
        DWORD ImageSubsystem;
        DWORD ImageSubsystemMajorVersion;
        T ImageSubsystemMinorVersion;
        T ActiveProcessAffinityMask;
        T GdiHandleBuffer[peb_traits<PTR_TYPE>::A];
        T PostProcessInitRoutine;
        T TlsExpansionBitmap;
        DWORD TlsExpansionBitmapBits[32];
        T SessionId;
        ULARGE_INTEGER AppCompatFlags;
        ULARGE_INTEGER AppCompatFlagsUser;
        T pShimData;
        T AppCompatInfo;
        UNICODE_STRING_T<T> CSDVersion;
        T ActivationContextData;
        T ProcessAssemblyStorageMap;
        T SystemDefaultActivationContextData;
        T SystemAssemblyStorageMap;
        T MinimumStackCommit;
        T FlsCallback;
        LIST_ENTRY_T<T> FlsListHead;
        T FlsBitmap;
        DWORD FlsBitmapBits[4];
        T FlsHighIndex;
        T WerRegistrationData;
        T WerShipAssertPtr;
        T pContextData;
        T pImageHeaderHash;
        T TracingFlags;
    };

    typedef LDR_DATA_TABLE_ENTRY_T<uint32_t> LDR_DATA_TABLE_ENTRY32;
    typedef LDR_DATA_TABLE_ENTRY_T<uint64_t> LDR_DATA_TABLE_ENTRY64;

    typedef TEB_T<uint32_t> TEB32;
    typedef TEB_T<uint64_t> TEB64;

    typedef PEB_LDR_DATA_T<uint32_t> PEB_LDR_DATA32;
    typedef PEB_LDR_DATA_T<uint64_t> PEB_LDR_DATA64;

    typedef PEB_T<uint32_t> PEB32;
    typedef PEB_T<uint64_t> PEB64;

    typedef uint32_t PID_TYPE;

    template<class T>
    struct PROCESS_BASIC_INFORMATION
    {
        union
        {
            PVOID Reserved1;
            T     dymmy1;
        };
        union
        {
            PEB_T<T>* PebBaseAddress;
            T         PebBaseAddressT;
        };
        union
        {
            PVOID Reserved2[2];
            T     dymmy2[2];
        };
        union
        {
            ULONG_PTR UniqueProcessId;
            T         dymmy3;
        };
        union
        {
            PVOID Reserved3;
            T     dymmy4;
        };
    };
}

#pragma pack(pop)
