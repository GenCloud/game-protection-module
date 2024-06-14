#ifndef _TRAY_H_
#define _TRAY_H_

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <time.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <icmpapi.h>
#include <io.h>

#include "resource.h"

using namespace std;

class Tray
{
	public:
		static BOOL CreateSplash();
		static BOOL LoadTrayIcon(HINSTANCE hInst, unsigned int id);
		static VOID FreeTrayIcon(unsigned int id);
};

#endif