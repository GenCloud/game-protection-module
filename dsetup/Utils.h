#ifndef _UTILS_H_
#define _UTILS_H_

#include <string>
#include <cstdio>
#include <sstream>
#include <vector>
#include <cstdint>
#include <winsock2.h>

using namespace std;

#pragma comment(lib, "Ws2_32.lib")

#define MAX_TEMP_PATH 300

typedef struct _DISCORD_APPLICATION
{
	IDiscordCore* core;
	IDiscordUserManager* users;
	IDiscordActivityManager* activities;
} DISCORD_APPLICATION, *PDS_APPLICATION;

class Utils
{
public:
	static string ToLower(string p_sString);
	static VOID ErrorExit(char* msg);

	static INT Guard_strcmp(LPCSTR p1, LPCSTR p2);
	static LPSTR Guard_strcat(LPSTR s1, LPCSTR s2);
	static LPCWSTR Guard_wcsistr(LPCWSTR s1, LPCWSTR s2);
	static LPWSTR Guard_wcscpy(LPWSTR s1, LPCWSTR s2);
	static LPWSTR Guard_wcscat(LPWSTR s1, LPCWSTR s2);
};

#endif