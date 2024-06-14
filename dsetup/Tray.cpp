#include "stdafx.h"
#include "Splash.h"
#include "tray.h"

#include <shellapi.h>
#include <windows.h>

HWND hWND;
HANDLE ghMutex;

LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProcW(hWnd, uMsg, wParam, lParam);
}

BOOL Tray::CreateSplash()
{
	CSplash splash(TEXT(".\\splash.bmp"), RGB(128, 128, 128));
	splash.ShowSplash();

	Sleep(3500);

	splash.CloseSplash();
	return true;
}

BOOL Tray::LoadTrayIcon(HINSTANCE hInst, unsigned int id)
{
	WNDCLASSEXA wcx;
	NOTIFYICONDATAA niData;

	memset(&wcx, 0, sizeof(WNDCLASSEXA));

	wcx.cbSize = sizeof(wcx);
	wcx.lpfnWndProc = WndProc;
	wcx.hInstance = hInst;
	wcx.lpszClassName = "tray_icon";

	if ((RegisterClassExA(&wcx) == 0) && (GetLastError() != ERROR_CLASS_ALREADY_EXISTS))
		return false;

	if ((hWND = CreateWindowExA(0, "tray_icon", 0, 0, 0, 0, 0, 0, 0, 0, hInst, 0)) == 0)
		return false;

	memset(&niData, 0, sizeof(NOTIFYICONDATAA));

	niData.cbSize = sizeof(NOTIFYICONDATAA);
	niData.uID = id;
	niData.uFlags = NIF_ICON | NIF_TIP;
	niData.hWnd = hWND;
	strcpy_s(niData.szTip, "Jamoa Games");

	niData.hIcon = (HICON)LoadImageA(hInst, MAKEINTRESOURCEA(IDI_ICON1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);

	if (!Shell_NotifyIconA(NIM_ADD, &niData))
		return false;

	return true;
}

VOID Tray::FreeTrayIcon(unsigned int id)
{
	NOTIFYICONDATAA niData;

	memset(&niData, 0, sizeof(NOTIFYICONDATAA));
	niData.cbSize = sizeof(NOTIFYICONDATAA);
	niData.hWnd = hWND;
	niData.uID = id;

	Shell_NotifyIconA(NIM_DELETE, &niData);

	CloseHandle(ghMutex);
}