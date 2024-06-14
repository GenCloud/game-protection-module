#include <windows.h>
#include <iostream>
#include <assert.h>
#include <psapi.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <time.h>
#include <queue>
#include <map>

#include "ThemidaSDK.h"
#include "ntstruct.h"
#include "GuardOptions.h"
#include "Hook.h"
#include "Utils.h"

#define CURRENT_PROCESS ((HANDLE)-1)

#define PAGE_SIZE 0x1000

#define MODULE_FIRST 0
#define MODULE_EXE 0
#define MODULE_NTDLL 1
#define MODULE_KERNEL32 2
#define MODULE_KERNELBASE 3
#define MODULE_LAST 3

#define TO_STRING(param) #param
#define APICALL(api_name) ((decltype(&api_name)) Guard_GetApi(TO_STRING(api_name)))
#define APICALL_FROM_MODULE(index, api_name) ((decltype(&api_name)) Guard_GetApi(TO_STRING(api_name), index))

#define LLKHF_LOWER_IL_INJECTED 0x00000002
#define LLMHF_LOWER_IL_INJECTED 0x00000002

#ifdef _WIN64
#define MEMORY_END 0x7FFFFFFF0000
#else
#define MEMORY_END 0x7FFF0000
#endif

typedef struct _GUARD_EVENT
{
    REPORT_CODE code;

    WCHAR module_name1[MAX_PATH];
    WCHAR module_name2[MAX_PATH];
    PVOID module_path1;
    PVOID module_path2;

    uint64_t tm;

} GUARD_EVENT, * PGUARD_EVENT;

// GuardLog.cpp
unsigned int Guard_FlushQueue(unsigned char* buf);
VOID Guard_Report(DWORD flag, REPORT_CODE code, PVOID data1, PVOID data2);

// GuardUtils.cpp
DWORD Guard_GetThreadStartAddress(HANDLE hThread);
PVOID Guard_GetNextModule(PLDR_MODULE pmodule_info);
HMODULE Guard_GetModuleHandleW(LPCWSTR module_path);
PVOID GetModuleBaseFromPtr(PVOID ptr, PTR_CHECK type);
LPWSTR Guard_GetModulePath(DWORD module_index);
PVOID Guard_GetProcAddress(HMODULE hmodule, LPCSTR proc_name);
PVOID Guard_GetApi(LPCSTR api_name, DWORD module_index = 0);
NTSTATUS Guard_QueryMemory(PVOID ptr, PVOID buffer, SIZE_T buffer_size, MEMORY_INFORMATION_CLASS type);
DWORD GetThreadOwnerProcessId(DWORD dwThreadID);
BOOL IsLoadedAddress(DWORD dwAddress);
BOOL IsSuspendedThread(DWORD dwThreadId);

// ProcessGuard.cpp
VOID LdrInitializeThunk_t(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);

VOID GuardThreads();

PVOID GetModuleAddressFromName(const wchar_t* c_wszName);
ULONG NTAPI RtlGetFullPathName_U_t(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName);

VOID GuardInject();

VOID DebugCallback(PEXCEPTION_POINTERS e);
LONG WINAPI Guard_ExceptionHandler(PEXCEPTION_POINTERS e);

VOID GuardDebugger();

VOID InitAntiMacro();
VOID DestroyAntiMacro();