#include "stdafx.h"
#include "tray.h"
#include "splash.h"
#include "ProcessGuard.h"
#include <Windows.h>

VOID InitConsole(VOID)
{
	AllocConsole();

	stdout->_file = _open_osfhandle((intptr_t)GetStdHandle(STD_OUTPUT_HANDLE), 0);
	stdin->_file = _open_osfhandle((intptr_t)GetStdHandle(STD_INPUT_HANDLE), 0);
	stderr->_file = _open_osfhandle((intptr_t)GetStdHandle(STD_ERROR_HANDLE), 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD callReason, LPVOID lpReserved)
{
	switch (callReason)
	{
		case DLL_PROCESS_ATTACH: {
			//Tray::CreateSplash();

			//Tray::LoadTrayIcon(hModule, 1);

			DisableThreadLibraryCalls(hModule);
			CreateThread(NULL, 0, InitThread, NULL, 0, 0);

#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG) || OPT_ENABLED(OPT_CIPHER_EVENTS_LOG) || OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG) || OPT_ENABLED(OPT_SEND_STRINGS_LOG) || OPT_ENABLED(OPT_OPCODE_PRINT_LOG) || OPT_ENABLED(OPT_DISCORD_EVENTS_LOG)
			InitConsole();
#endif
			InitAntiMacro();

			GuardThreads();
			GuardInject();
			GuardDebugger();

			break;
		}
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH: {
			//Tray::FreeTrayIcon(1);

			DestroyAntiMacro();

#if OPT_ENABLED(OPT_GUARD_EVENTS_LOG) || OPT_ENABLED(OPT_CIPHER_EVENTS_LOG) || OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG) || OPT_ENABLED(OPT_SEND_STRINGS_LOG) || OPT_ENABLED(OPT_OPCODE_PRINT_LOG) || OPT_ENABLED(OPT_DISCORD_EVENTS_LOG)
			FreeConsole();
#endif
			break;
		}
	}
	return TRUE;
}