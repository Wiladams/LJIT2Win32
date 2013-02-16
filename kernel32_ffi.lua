local ffi = require "ffi"
local C = ffi.C

require "WinBase"
local kernel32 = ffi.load("kernel32");

local kernel32_ffi = {
	PROCESS_HEAP_REGION             =0x0001;
	PROCESS_HEAP_UNCOMMITTED_RANGE  =0x0002;
	PROCESS_HEAP_ENTRY_BUSY         =0x0004;
	PROCESS_HEAP_ENTRY_MOVEABLE     =0x0010;
	PROCESS_HEAP_ENTRY_DDESHARE     =0x0020;

	HEAP_NO_SERIALIZE				= 0x00000001;
	HEAP_GENERATE_EXCEPTIONS		= 0x00000004;
	HEAP_ZERO_MEMORY				= 0x00000008;
	HEAP_REALLOC_IN_PLACE_ONLY		= 0x00000010;
	HEAP_CREATE_ENABLE_EXECUTE		= 0x00040000;
}

--[[
BOOL HeapSetInformation (HANDLE HeapHandle,
    HEAP_INFORMATION_CLASS HeapInformationClass,
    PVOID HeapInformation,
    SIZE_T HeapInformationLength);

BOOL HeapQueryInformation (HANDLE HeapHandle,
    HEAP_INFORMATION_CLASS HeapInformationClass,
    __out_bcount_part_opt(HeapInformationLength, *ReturnLength) PVOID HeapInformation,
    SIZE_T HeapInformationLength,
    __out_opt PSIZE_T ReturnLength
    );
--]]

ffi.cdef[[
typedef struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union {
        struct {
            DWORD Offset;
            DWORD OffsetHigh;
        };

        PVOID Pointer;
    };

    HANDLE hEvent;
} OVERLAPPED, *LPOVERLAPPED;

// Taken from WinNT.h
typedef struct _RTL_SRWLOCK 
{
    PVOID Ptr;
} RTL_SRWLOCK, *PRTL_SRWLOCK;

// Taken from WinBase.h
typedef RTL_SRWLOCK SRWLOCK, *PSRWLOCK;
]]

ffi.cdef[[


typedef struct _PROCESS_HEAP_ENTRY {
    PVOID lpData;
    DWORD cbData;
    BYTE cbOverhead;
    BYTE iRegionIndex;
    WORD wFlags;
    union {
        struct {
            HANDLE hMem;
            DWORD dwReserved[ 3 ];
        } Block;
        struct {
            DWORD dwCommittedSize;
            DWORD dwUnCommittedSize;
            LPVOID lpFirstBlock;
            LPVOID lpLastBlock;
        } Region;
    } DUMMYUNIONNAME;
} PROCESS_HEAP_ENTRY, *LPPROCESS_HEAP_ENTRY, *PPROCESS_HEAP_ENTRY;


HANDLE HeapCreate(DWORD flOptions,
    SIZE_T dwInitialSize,
    SIZE_T dwMaximumSize);


BOOL HeapDestroy(HANDLE hHeap);


LPVOID HeapAlloc(
    HANDLE hHeap,
    DWORD dwFlags,
    SIZE_T dwBytes);


LPVOID HeapReAlloc(HANDLE hHeap,
	DWORD dwFlags,
    LPVOID lpMem,
	SIZE_T dwBytes);

BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

SIZE_T HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);

BOOL HeapValidate(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);

SIZE_T HeapCompact(HANDLE hHeap, DWORD dwFlags);

HANDLE GetProcessHeap( void );

DWORD GetProcessHeaps(DWORD NumberOfHeaps, PHANDLE ProcessHeaps);

BOOL HeapLock(HANDLE hHeap);

BOOL HeapUnlock(HANDLE hHeap);

BOOL HeapWalk(HANDLE hHeap, PROCESS_HEAP_ENTRY * lpEntry);

]]


-- File System Calls
--
ffi.cdef[[
DWORD GetCurrentDirectoryA(DWORD nBufferLength, LPTSTR lpBuffer);

HANDLE CreateFileA(LPCTSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
);

BOOL GetFileInformationByHandle(HANDLE hFile,
    PBY_HANDLE_FILE_INFORMATION lpFileInformation);

BOOL GetFileTime(HANDLE hFile,
	LPFILETIME lpCreationTime,
	LPFILETIME lpLastAccessTime,
	LPFILETIME lpLastWriteTime);

BOOL FileTimeToSystemTime(const FILETIME* lpFileTime, LPSYSTEMTIME lpSystemTime);

BOOL DeleteFileW(LPCTSTR lpFileName);

BOOL MoveFileW(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName);

	/*
HFILE WINAPI OpenFile(LPCSTR lpFileName,
	LPOFSTRUCT lpReOpenBuff,
	UINT uStyle);
*/
]]

ffi.cdef[[
typedef DWORD  (*LPTHREAD_START_ROUTINE)(LPVOID lpParameter);
]]



ffi.cdef[[

DWORD GetLastError();

HMODULE GetModuleHandleA(LPCSTR lpModuleName);

BOOL CloseHandle(HANDLE hObject);

HANDLE CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes,
		BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);


HANDLE CreateIoCompletionPort(HANDLE FileHandle,
	HANDLE ExistingCompletionPort,
	ULONG_PTR CompletionKey,
	DWORD NumberOfConcurrentThreads);

BOOL GetQueuedCompletionStatus(
    HANDLE CompletionPort,
    LPDWORD lpNumberOfBytesTransferred,
    PULONG_PTR lpCompletionKey,
    LPOVERLAPPED *lpOverlapped,
    DWORD dwMilliseconds
    );

BOOL PostQueuedCompletionStatus(
	HANDLE CompletionPort,
	DWORD dwNumberOfBytesTransferred,
	ULONG_PTR dwCompletionKey,
	LPOVERLAPPED lpOverlapped
);


HANDLE CreateThread(
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	size_t dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	DWORD dwCreationFlags,
	LPDWORD lpThreadId);


DWORD GetCurrentThreadId(void);
DWORD ResumeThread(HANDLE hThread);
BOOL SwitchToThread(void);
DWORD SuspendThread(HANDLE hThread);


void * GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

BOOL QueryPerformanceFrequency(int64_t *lpFrequency);
BOOL QueryPerformanceCounter(int64_t *lpPerformanceCount);

//	DWORD QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);

void Sleep(DWORD dwMilliseconds);

DWORD SleepEx(DWORD dwMilliseconds, BOOL bAlertable);
]]




--[[
	WinNls.h

	Defined in Kernel32
--]]

CP_ACP 		= 0		-- default to ANSI code page
CP_OEMCP		= 1		-- default to OEM code page
CP_MACCP		= 2		-- default to MAC code page
CP_THREAD_ACP	= 3		-- current thread's ANSI code page
CP_SYMBOL		= 42	-- SYMBOL translations

ffi.cdef[[
int MultiByteToWideChar(UINT CodePage,
    DWORD    dwFlags,
    LPCSTR   lpMultiByteStr, int cbMultiByte,
    LPWSTR  lpWideCharStr, int cchWideChar);


int WideCharToMultiByte(UINT CodePage,
    DWORD    dwFlags,
	LPCWSTR  lpWideCharStr, int cchWideChar,
    LPSTR   lpMultiByteStr, int cbMultiByte,
    LPCSTR   lpDefaultChar,
    LPBOOL  lpUsedDefaultChar);
]]


return kernel32_ffi

