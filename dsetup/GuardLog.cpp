#include "stdafx.h"
#include "ProcessGuard.h"
#include "Utils.h"

queue<GUARD_EVENT> GUARD_EVENTS_QUEUE;

unsigned int Guard_FlushQueue(unsigned char *buf)
{
	VM_START_WITHLEVEL(15)

	if (!GUARD_EVENTS_QUEUE.empty()) {
		int size = 0;

		*(unsigned int*)(buf + size) = GUARD_EVENTS_QUEUE.size();
		size += 4;

		while (!GUARD_EVENTS_QUEUE.empty()) {
			GUARD_EVENT event = GUARD_EVENTS_QUEUE.front();

			*(unsigned int*)(buf + size) = (uint32_t) event.code;
			size += 4;

			*(unsigned __int64*)(buf + size) = (uint64_t) event.tm;
			size += 8;

			WCHAR* module_name1 = L"";
			if (wcslen(event.module_name1) > 0 && sizeof(event.module_name1) > 0)
			{
				module_name1 = event.module_name1;
			}
			
			memcpy(buf + size, module_name1, wcslen(module_name1) * 2 + 2);
			size += wcslen(module_name1) * 2 + 2;

			WCHAR* module_name2 = L"";
			if (wcslen(event.module_name2) > 0 && sizeof(event.module_name2) > 0)
			{
				module_name2 = event.module_name2;
			}

			memcpy(buf + size, module_name2, wcslen(module_name2) * 2 + 2);
			size += wcslen(module_name2) * 2 + 2;

			*(unsigned int*)(buf + size) = (uint32_t)event.module_path1;
			size += 4;

			*(unsigned int*)(buf + size) = (uint32_t)event.module_path2;
			size += 4;

			GUARD_EVENTS_QUEUE.pop();
		}

		return size;
	}

	VM_END

	return -1;
}

VOID Guard_Report(DWORD flag, REPORT_CODE code, PVOID data1, PVOID data2)
{
	VM_START_WITHLEVEL(7)

	WCHAR module_path1[MAX_PATH] = L"";
	WCHAR module_path2[MAX_PATH] = L"";

	time_t t = time(NULL);
	time_t millis = t * 1000;

	PTR_CHECK prtCheck;
	if (code == REPORT_MEMORY_MOD || code == REPORT_MEMORY_VP || code == REPORT_MEMORY_VA || code == REPORT_MEMORY_WPM || code == REPORT_MEMORY_RPM)
	{
		prtCheck = PC_EXECUTABLE;
	}
	else
	{
		prtCheck = PC_IMAGE_SIZE;
	}

	PVOID module_base1 = GetModuleBaseFromPtr(data1, prtCheck);
	PVOID module_base2 = GetModuleBaseFromPtr(data2, prtCheck);

	GUARD_EVENT guardEvent;
	guardEvent.code = code;
	guardEvent.tm = millis;

	LDR_MODULE module_info = { 0, };
	for (DWORD i = 0; Guard_GetNextModule(&module_info); ++i)
	{
		if (prtCheck == PC_EXECUTABLE)
		{
			if (module_info.BaseDllName.Length > 0) 
			{
				Utils::Guard_wcscpy(guardEvent.module_name1, module_info.BaseDllName.Buffer);
				Utils::Guard_wcscpy(guardEvent.module_name2, module_info.BaseDllName.Buffer);
			}

			if (module_info.FullDllName.Length > 0) 
			{
				Utils::Guard_wcscpy(module_path1, module_info.FullDllName.Buffer);
				Utils::Guard_wcscpy(module_path2, module_info.FullDllName.Buffer);
			}
		}
		else
		{
			if (module_base1 == module_info.BaseAddress)
			{
				if (module_info.BaseDllName.Length > 0) 
				{
					Utils::Guard_wcscpy(guardEvent.module_name1, module_info.BaseDllName.Buffer);
				}

				if (module_info.FullDllName.Length > 0) 
				{
					Utils::Guard_wcscpy(module_path1, module_info.FullDllName.Buffer);
				}
			}

			if (module_base2 == module_info.BaseAddress)
			{
				if (module_info.BaseDllName.Length > 0) 
				{
					Utils::Guard_wcscpy(guardEvent.module_name2, module_info.BaseDllName.Buffer);
				}

				if (module_info.FullDllName.Length > 0) 
				{
					Utils::Guard_wcscpy(module_path2, module_info.FullDllName.Buffer);
				}
			}
		}
	}
	
	guardEvent.module_path1 = (PVOID) GetOffset(Guard_GetModuleHandleW(module_path1), data1);
	guardEvent.module_path2 = (PVOID) GetOffset(Guard_GetModuleHandleW(module_path2), data2);

	GUARD_EVENTS_QUEUE.push(guardEvent);

#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG)
	printf(
		"Pid : %d / Code : 0x%08X / %S 0x%p / %S 0x%p\n",
		GetCurrentProcessId(),
		code,
		guardEvent.module_name1, guardEvent.module_path1,
		guardEvent.module_name2, guardEvent.module_path2
	);
#endif

	VM_END
}