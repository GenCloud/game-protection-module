#include "stdafx.h"
#include "Utils.h"
#include "ThreadEnum.h"
#include "ProcessGuard.h"

DWORD Guard_GetThreadStartAddress(HANDLE hThread)
{
	DWORD start_address = NULL;
	APICALL(NtQueryInformationThread)(hThread, (THREADINFOCLASS)ThreadQuerySetWin32StartAddress, &start_address, sizeof(start_address), 0);
	return start_address;
}

PVOID Guard_GetApi(LPCSTR api_name, DWORD module_index)
{
	if (module_index) 
	{
		return Guard_GetProcAddress(Guard_GetModuleHandleW(Guard_GetModulePath(module_index)), api_name);
	}

	PVOID api = Guard_GetProcAddress(Guard_GetModuleHandleW(Guard_GetModulePath(MODULE_NTDLL)), api_name);
	if (!api)
	{
		api = Guard_GetProcAddress(Guard_GetModuleHandleW(Guard_GetModulePath(MODULE_KERNELBASE)), api_name);
	}

	if (!api)
	{
		api = Guard_GetProcAddress(Guard_GetModuleHandleW(Guard_GetModulePath(MODULE_KERNEL32)), api_name);
	}

	return api;
}

PVOID Guard_GetNextModule(PLDR_MODULE pmodule_info)
{
	PLDR_MODULE flink;
	if (!pmodule_info->BaseAddress)
	{
#ifdef _WIN64
		PTEB teb = (PTEB)__readgsqword(0x30);
#else
		PTEB teb = (PTEB)__readfsdword(0x18);
#endif
		flink = (PLDR_MODULE)teb->Peb->Ldr->InMemoryOrderModuleList.Flink;
	}
	else
	{
		flink = (PLDR_MODULE)pmodule_info->InMemoryOrderModuleList.Flink;
	}

	PLDR_MODULE base = (PLDR_MODULE)GetPtr(flink, GetOffset(&flink->InMemoryOrderModuleList, flink));
	*pmodule_info = *base;

	return pmodule_info->BaseAddress;
}

PVOID Guard_GetProcAddress(HMODULE hmodule, LPCSTR proc_name)
{
	PIMAGE_NT_HEADERS pnh = GetNtHeader(hmodule);
	PIMAGE_DATA_DIRECTORY pdd = &pnh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY ped = (PIMAGE_EXPORT_DIRECTORY)GetPtr(hmodule, pdd->VirtualAddress);

	PDWORD func_table = (PDWORD)GetPtr(hmodule, ped->AddressOfFunctions);
	PWORD ordinal_table = (PWORD)GetPtr(hmodule, ped->AddressOfNameOrdinals);

	if ((DWORD_PTR)proc_name <= 0xFFFF)
	{
		WORD ordinal = (WORD)IMAGE_ORDINAL((DWORD_PTR)proc_name);
		ordinal -= (WORD)ped->Base;
		if (ordinal < ped->NumberOfFunctions)
			return GetPtr(hmodule, func_table[ordinal]);
	}
	else
	{
		PDWORD func_name_table = (PDWORD)GetPtr(hmodule, ped->AddressOfNames);
		for (DWORD i = 0; i < ped->NumberOfNames; ++i)
			if (!Utils::Guard_strcmp(proc_name, (LPCSTR)GetPtr(hmodule, func_name_table[i])))
				return GetPtr(hmodule, func_table[ordinal_table[i]]);
	}

	return NULL;
}

LPWSTR Guard_GetModulePath(DWORD module_index)
{
	static WCHAR module_path[MODULE_LAST + 1][MAX_PATH] = { 0, };

	if (!module_path[module_index][0])
	{
		LDR_MODULE module_info = { 0, };
		for (DWORD i = MODULE_FIRST; i <= module_index; i++)
			Guard_GetNextModule(&module_info);

		Utils::Guard_wcscpy(module_path[module_index], module_info.FullDllName.Buffer);
	}

	return module_path[module_index];
}

HMODULE Guard_GetModuleHandleW(LPCWSTR module_path)
{
	LDR_MODULE module_info = { 0, };
	while (Guard_GetNextModule(&module_info))
	{
		if (!module_path)
			return module_info.BaseAddress;

		if (Utils::Guard_wcsistr(module_path, module_info.BaseDllName.Buffer))
			return module_info.BaseAddress;
	}

	return NULL;
}

PVOID GetModuleBaseFromPtr(PVOID ptr, PTR_CHECK type)
{
	LDR_MODULE module_info = { 0, };
	for (DWORD i = 0; Guard_GetNextModule(&module_info); ++i)
	{
		PVOID module_base = module_info.BaseAddress;
		PIMAGE_NT_HEADERS nt = GetNtHeader(module_base);
		PVOID sptr;
		PVOID eptr;

		if (type == PC_EXECUTABLE)
		{
			PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
			for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
			{
				if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
				{
					sptr = GetPtr(module_base, sec[i].VirtualAddress);
					eptr = GetPtr(sptr, sec[i].Misc.VirtualSize);
					if (sptr <= ptr && ptr < eptr)
						return module_base;
				}
			}
		}

		if (type == PC_IMAGE_SIZE)
		{
			sptr = module_base;
			eptr = GetPtr(sptr, nt->OptionalHeader.SizeOfImage);
			if (sptr <= ptr && ptr < eptr)
				return module_base;
		}
	}

	return nullptr;
}

DWORD GetThreadOwnerProcessId(DWORD dwThreadID)
{
	auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (!hSnap || hSnap == INVALID_HANDLE_VALUE)
		return 0;

	THREADENTRY32 ti = { 0 };
	ti.dwSize = sizeof(ti);

	if (Thread32First(hSnap, &ti))
	{
		do {
			if (dwThreadID == ti.th32ThreadID) {
				CloseHandle(hSnap);
				return ti.th32OwnerProcessID;
			}
		} while (Thread32Next(hSnap, &ti));
	}

	CloseHandle(hSnap);

	return 0;
}

BOOL IsLoadedAddress(DWORD dwAddress)
{
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InMemoryOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->Ldr->InMemoryOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (dwAddress == (DWORD)Current->DllBase)
			return true;

		CurrentEntry = CurrentEntry->Flink;
	}
	return false;
}

BOOL IsSuspendedThread(DWORD dwThreadId)
{
	auto threadEnumerator = new CThreadEnumerator(GetCurrentProcessId());
	if (threadEnumerator == nullptr) {
		delete threadEnumerator;
		return true;
	}

	auto systemThreadOwnerProcInfo = threadEnumerator->GetProcInfo();
	if (systemThreadOwnerProcInfo == nullptr) {
		delete threadEnumerator;
		return true;
	}

	auto systemThreadInfo = threadEnumerator->FindThread(systemThreadOwnerProcInfo, dwThreadId);
	if (systemThreadInfo == nullptr) {
		delete threadEnumerator;
		return true;
	}

	if (systemThreadInfo->ThreadState == Waiting && systemThreadInfo->WaitReason == Suspended) {
		delete threadEnumerator;
		return true;
	}

	delete threadEnumerator;
	return false;
}

PVOID GetModuleAddressFromName(const wchar_t* c_wszName)
{
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InMemoryOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->Ldr->InMemoryOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (wcsstr(Current->FullDllName.Buffer, c_wszName))
			return Current->DllBase;

		CurrentEntry = CurrentEntry->Flink;
	}
	return nullptr;
}

NTSTATUS Guard_QueryMemory(PVOID ptr, PVOID buffer, SIZE_T buffer_size, MEMORY_INFORMATION_CLASS type)
{
	return APICALL(NtQueryVirtualMemory)(CURRENT_PROCESS, ptr, type, buffer, buffer_size, NULL);
}