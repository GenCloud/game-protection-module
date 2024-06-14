#include "stdafx.h"
#include "ProcessGuard.h"

typedef NTSTATUS(__stdcall* NtAllocateVirtualMemoryT)(HANDLE, PVOID*, ULONG, PULONG, ULONG, ULONG);
static NtAllocateVirtualMemoryT NtAllocateVirtualMemory = NULL;

typedef ULONG(NTAPI* RtlGetFullPathName_U)(PCWSTR, ULONG, PWSTR, PWSTR*);
static RtlGetFullPathName_U RtlGetFullPathName_U_ = nullptr;

typedef NTSTATUS(WINAPI* lpNtQueryInformationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);
typedef void(*LdrInitializeThunk)(PCONTEXT, PVOID, PVOID);

static LdrInitializeThunk LdrInitializeThunk_ = nullptr;

BOOL IsSameFunction(PVOID f1, PVOID f2)
{
	DWORD count = 0, i = 0;

	for (; *((BYTE*)f1 + i) != 0xCC; i++)
		if (*((BYTE*)f1 + i) == *((BYTE*)f2 + i))
			count++;

	return count == i;
}

VOID LdrInitializeThunk_t(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	MUTATE_START

	DWORD dbgCheckFlag;
	CHECK_DEBUGGER(dbgCheckFlag, 0x12345678);
	if (dbgCheckFlag != 0x12345678) {
		Utils::ErrorExit("[ERROR] -1\r\n");
		return;
}

	DWORD vmCheckFlag;
	CHECK_VIRTUAL_PC(vmCheckFlag, 0x12345678);
	if (vmCheckFlag != 0x12345678) {
		Utils::ErrorExit("[ERROR] -2\r\n");
		return;
	}

	auto dwStartAddress = Guard_GetThreadStartAddress(NtCurrentThread);

#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
	printf("[*] A thread attached to process! Start address: %p\n", (void*)dwStartAddress);
#endif

	auto dwThreadId = GetThreadId(NtCurrentThread);

#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
	printf("\t* Thread: %u - Suspended: %d\n", dwThreadId, IsSuspendedThread(dwThreadId));
#endif

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;
	if (GetThreadContext(NtCurrentThread, &ctx))
	{
		auto bHasDebugRegister = (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr7);

		if (ctx.Dr0) {
			Guard_Report(OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_0, (PVOID)ctx.Dr0, (PVOID)ctx.Dr7);
#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
			printf("\t* Context; Has debug register: %d Eip: %p Eax: %p\n", 1, (void*)ctx.Eip, (void*)ctx.Eax);
#endif
		} else if (ctx.Dr1) {
			Guard_Report(OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_1, (PVOID)ctx.Dr1, (PVOID)ctx.Dr7);
#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
			printf("\t* Context; Has debug register: %d Eip: %p Eax: %p\n", 1, (void*)ctx.Eip, (void*)ctx.Eax);
#endif
		} else if (ctx.Dr2) {
			Guard_Report(OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_2, (PVOID)ctx.Dr2, (PVOID)ctx.Dr7);
#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
			printf("\t* Context; Has debug register: %d Eip: %p Eax: %p\n", 1, (void*)ctx.Eip, (void*)ctx.Eax);
#endif
		} else if (ctx.Dr3) {
			Guard_Report(OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_3, (PVOID)ctx.Dr3, (PVOID)ctx.Dr7);
#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
			printf("\t* Context; Has debug register: %d Eip: %p Eax: %p\n", 1, (void*)ctx.Eip, (void*)ctx.Eax);
#endif
		} else if (ctx.Dr7) {
			Guard_Report(OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_7, (PVOID)ctx.Dr7, (PVOID)ctx.Dr7);
#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
			printf("\t* Context; Has debug register: %d Eip: %p Eax: %p\n", 1, (void*)ctx.Eip, (void*)ctx.Eax);
#endif
		}
	}

	MODULEINFO user32ModInfo = { 0 };
	if (GetModuleInformation(NtCurrentProcess, LoadLibraryA("user32"), &user32ModInfo, sizeof(user32ModInfo)))
	{
		DWORD dwUser32Low = (DWORD)user32ModInfo.lpBaseOfDll;
		DWORD dwUser32Hi = (DWORD)user32ModInfo.lpBaseOfDll + user32ModInfo.SizeOfImage;
		if (dwStartAddress >= dwUser32Low && dwStartAddress <= dwUser32Hi) {
			Guard_Report(OPT_THREAD_CHECK, REPORT_RANGE_CALL_USER32, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
			printf("# WARNING # dwStartAddress in User32.dll\n");
#endif
		}
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNEL32, LoadLibraryA), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryA, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNEL32, LoadLibraryW), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryW, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNEL32, LoadLibraryExA), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExA, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNEL32, LoadLibraryExW), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_DLL_INJECTION_KERNEL32_LoadLibraryExW, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNELBASE, LoadLibraryA), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryA, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNELBASE, LoadLibraryW), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryW, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNELBASE, LoadLibraryExA), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExA, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNELBASE, LoadLibraryExW), (PVOID)dwStartAddress)){
		Guard_Report(OPT_THREAD_CHECK, REPORT_DLL_INJECTION_KERNELBASE_LoadLibraryExW, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNEL32, WriteProcessMemory), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_MEMORY_WPM, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNEL32, ReadProcessMemory), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_MEMORY_RPM, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNEL32, VirtualProtect), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_MEMORY_VP, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_KERNEL32, VirtualAlloc), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_MEMORY_VA, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_NTDLL, LdrLoadDll), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_DLL_INJECTION_NTDLL_LdrLoadDll, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_NTDLL, NtCreateThreadEx), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_DLL_INJECTION_NTDLL_NtCreateThreadEx, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (IsSameFunction(APICALL_FROM_MODULE(MODULE_NTDLL, RtlUserThreadStart), (PVOID)dwStartAddress)) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_DLL_INJECTION_NTDLL_RtlUserThreadStart, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (dwStartAddress == (DWORD)GetProcAddress(LoadLibraryA("ntdll"), "NtCreateThread")) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_DLL_INJECTION_NTDLL_NtCreateThread, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	if (dwStartAddress == (DWORD)GetProcAddress(LoadLibraryA("ntdll"), "RtlCreateUserThread")) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_DLL_INJECTION_NTDLL_RtlCreateUserThread, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
	}

	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if (VirtualQuery((LPCVOID)dwStartAddress, &mbi, sizeof(mbi)))
	{
		if (mbi.Type != MEM_IMAGE) {
			Guard_Report(OPT_THREAD_CHECK, REPORT_MEMORY_MOD, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
			printf("# WARNING # mbi.Type != MEM_IMAGE\n");
#endif
		}

		if (dwStartAddress == (DWORD)mbi.AllocationBase) {
			Guard_Report(OPT_THREAD_CHECK, REPORT_MEMORY_MOD, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
			printf("# WARNING # dwStartAddress == mbi.AllocationBase\n");
#endif
		}
	}

	if (IsLoadedAddress(dwStartAddress)) {
#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
		printf("# WARNING # IsLoadedAddress(dwStartAddress)\n");
#endif
	}

	if (GetThreadOwnerProcessId(dwThreadId) != GetCurrentProcessId()) {
		Guard_Report(OPT_THREAD_CHECK, REPORT_THREAD_OWNER, (PVOID) dwStartAddress, (PVOID)(SIZE_T)TC_ThreadCallback);
#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
		printf("# WARNING # GetThreadOwnerProcessId(dwThreadId) != GetCurrentProcessId()\n");
#endif
	}

	IMAGE_SECTION_HEADER* pCurrentSecHdr = (IMAGE_SECTION_HEADER*)dwStartAddress;
	if (pCurrentSecHdr)
	{
		BOOL IsMonitored =
			(pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_READ) &&
			(pCurrentSecHdr->Characteristics & IMAGE_SCN_CNT_CODE) && !(pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_DISCARDABLE);

		if (IsMonitored) {
			Guard_Report(OPT_MEMORY_CHECK, REPORT_REMOTE_CODE_EXEC, pCurrentSecHdr, (PVOID)(SIZE_T)pCurrentSecHdr->Characteristics);

#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
			printf("# WARNING # Remote code execution!\n");
#endif
		}
	}

	MUTATE_END

	return LdrInitializeThunk_(NormalContext, SystemArgument1, SystemArgument2);
}

VOID GuardThreads()
{
	MUTATE_START

	auto hNtdll = LoadLibraryA("ntdll.dll");
	assert(hNtdll);

	LdrInitializeThunk LdrInitializeThunk_o = (LdrInitializeThunk) GetProcAddress(hNtdll, "LdrInitializeThunk");
	assert(LdrInitializeThunk_o);

	LdrInitializeThunk_ = (LdrInitializeThunk) splice((unsigned char*) LdrInitializeThunk_o, LdrInitializeThunk_t);

	DWORD dwOld = 0;
	auto bProtectRet = VirtualProtect(LdrInitializeThunk_, 5, PAGE_EXECUTE_READWRITE, &dwOld);
	assert(bProtectRet);

	MUTATE_END
}

ULONG NTAPI RtlGetFullPathName_U_t(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName)
{
	DWORD dbgCheckFlag;
	CHECK_DEBUGGER(dbgCheckFlag, 0x12345678);
	if (dbgCheckFlag != 0x12345678) {
		Utils::ErrorExit("[ERROR] -1\r\n");
		return false;
	}

	DWORD vmCheckFlag;
	CHECK_VIRTUAL_PC(vmCheckFlag, 0x12345678);
	if (vmCheckFlag != 0x12345678) {
		Utils::ErrorExit("[ERROR] -2\r\n");
		return false;
	}

#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
	printf("RtlGetFullPathName_U_t -> %ls - %u\n", FileName, Size);
#endif

	auto pModuleBase = GetModuleAddressFromName(FileName);
	if (pModuleBase) {
		Guard_Report(OPT_ANTI_DLL_INJECTION, REPORT_DLL_INJECTION_NTDLL_RtlGetFullPathName_U, (PVOID)pModuleBase, (PVOID)(SIZE_T)TC_DllCallback);

#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
		printf("Injected dll detected! Base: %p\n", pModuleBase);
#endif
	}

	return RtlGetFullPathName_U_(FileName, Size, Buffer, ShortName);
}

VOID GuardInject()
{
	MUTATE_START

	auto hNtdll = LoadLibraryA("ntdll.dll");
	assert(hNtdll);

	auto RtlGetFullPathName_U_o = (RtlGetFullPathName_U) GetProcAddress(hNtdll, "RtlGetFullPathName_U");
	assert(RtlGetFullPathName_U_o);

	RtlGetFullPathName_U_ = (RtlGetFullPathName_U) splice((unsigned char*) RtlGetFullPathName_U_o, RtlGetFullPathName_U_t);

	DWORD dwOld = 0;
	auto bProtectRet = VirtualProtect(RtlGetFullPathName_U_, 5, PAGE_EXECUTE_READWRITE, &dwOld);
	assert(bProtectRet);

	MUTATE_END
}

VOID DebugCallback(PEXCEPTION_POINTERS e)
{
	MUTATE_START

	if (e->ContextRecord->Dr0)
		Guard_Report(OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_0, (PVOID)e->ContextRecord->Dr0, (PVOID)e->ContextRecord->Dr7);
	else if (e->ContextRecord->Dr1)
		Guard_Report(OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_1, (PVOID)e->ContextRecord->Dr1, (PVOID)e->ContextRecord->Dr7);
	else if (e->ContextRecord->Dr2)
		Guard_Report(OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_2, (PVOID)e->ContextRecord->Dr2, (PVOID)e->ContextRecord->Dr7);
	else if (e->ContextRecord->Dr3)
		Guard_Report(OPT_ANTI_DEBUGGING, REPORT_DEBUG_HW_BREAKPOINT_3, (PVOID)e->ContextRecord->Dr3, (PVOID)e->ContextRecord->Dr7);
	else if (e->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
		Guard_Report(OPT_ANTI_DEBUGGING, REPORT_DEBUG_SW_BREAKPOINT, (PVOID)e->ExceptionRecord->ExceptionAddress, (PVOID)e->ExceptionRecord->ExceptionInformation[1]);
	else if (e->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
		Guard_Report(OPT_ANTI_DEBUGGING, REPORT_DEBUG_SINGLE_STEP, (PVOID)e->ExceptionRecord->ExceptionAddress, (PVOID)e->ExceptionRecord->ExceptionInformation[1]);
	else if (e->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		Guard_Report(OPT_ANTI_DEBUGGING, REPORT_DEBUG_PAGE_GUARD, (PVOID)e->ExceptionRecord->ExceptionAddress, (PVOID)e->ExceptionRecord->ExceptionInformation[1]);

	MUTATE_END
}

LONG WINAPI Guard_ExceptionHandler(PEXCEPTION_POINTERS e)
{
	DebugCallback(e);
	return EXCEPTION_CONTINUE_SEARCH;
}

VOID GuardDebugger()
{
	APICALL(RtlAddVectoredExceptionHandler)(1, Guard_ExceptionHandler);
}

static HHOOK s_hkMouseHook = 0;
static HHOOK s_hkKeyboardHook = 0;

LRESULT CALLBACK MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	MUTATE_START

	if (nCode == HC_ACTION)
	{
		if (wParam == WM_RBUTTONDOWN || wParam == WM_LBUTTONDOWN)
		{
			auto pHookData = (MSLLHOOKSTRUCT*)lParam;

			if ((pHookData->flags & LLMHF_INJECTED) == LLMHF_INJECTED) {
				auto dwStartAddress = Guard_GetThreadStartAddress(NtCurrentThread);
				Guard_Report(OPT_MACRO_CHECK, REPORT_LOW_LEVEL_MH, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_MacroCallback);
				return TRUE;
			}

			if ((pHookData->flags & LLMHF_LOWER_IL_INJECTED) == LLMHF_LOWER_IL_INJECTED) {
				auto dwStartAddress = Guard_GetThreadStartAddress(NtCurrentThread);
				Guard_Report(OPT_MACRO_CHECK, REPORT_LOW_LEVEL_MH, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_MacroCallback);
				return TRUE;
			}
		}
	}

	MUTATE_END

	return CallNextHookEx(s_hkMouseHook, nCode, wParam, lParam);
}

LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	MUTATE_START

	if (nCode == HC_ACTION)
	{
		if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)
		{
			auto pHookData = (KBDLLHOOKSTRUCT*)lParam;

			if ((pHookData->flags & LLKHF_INJECTED) == LLKHF_INJECTED) {
				auto dwStartAddress = Guard_GetThreadStartAddress(NtCurrentThread);
				Guard_Report(OPT_MACRO_CHECK, REPORT_LOW_LEVEL_KH, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_MacroCallback);
				return TRUE;
			}

			if ((pHookData->flags & LLKHF_LOWER_IL_INJECTED) == LLKHF_LOWER_IL_INJECTED) {
				auto dwStartAddress = Guard_GetThreadStartAddress(NtCurrentThread);
				Guard_Report(OPT_MACRO_CHECK, REPORT_LOW_LEVEL_KH, (PVOID)dwStartAddress, (PVOID)(SIZE_T)TC_MacroCallback);
				return TRUE;
			}
		}
	}

	MUTATE_END

	return CallNextHookEx(s_hkKeyboardHook, nCode, wParam, lParam);
}

DWORD WINAPI AntiMacroEx(LPVOID)
{
	MUTATE_START

	HINSTANCE hInstance = GetModuleHandle(NULL);
	s_hkMouseHook = SetWindowsHookExA(WH_MOUSE_LL, MouseHookProc, hInstance, NULL);
	s_hkKeyboardHook = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardHookProc, hInstance, NULL);

	if (s_hkMouseHook && s_hkKeyboardHook)
	{
		MSG message;
		while (GetMessageA(&message, NULL, 0, 0))
		{
			TranslateMessage(&message);
			DispatchMessageA(&message);
		}

		return 0;
	}

	UnhookWindowsHookEx(s_hkMouseHook);
	UnhookWindowsHookEx(s_hkKeyboardHook);

	MUTATE_END

	return 0;
}

VOID InitAntiMacro()
{
	CreateThread(NULL, 0, AntiMacroEx, NULL, 0, 0);
}

VOID DestroyAntiMacro()
{
	if (s_hkMouseHook)
	{
		UnhookWindowsHookEx(s_hkMouseHook);
		s_hkMouseHook = nullptr;
	}

	if (s_hkKeyboardHook)
	{
		UnhookWindowsHookEx(s_hkKeyboardHook);
		s_hkKeyboardHook = nullptr;
	}
}