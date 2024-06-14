#include "stdafx.h"
#include "Utils.h"

// Function to convert a string to lower

string Utils::ToLower(string p_sString)
{
	string result = "";

	for (size_t i = 0; i < p_sString.length(); i++)
	{
		if (p_sString[i] >= 65 && p_sString[i] <= 90) result += (char)(p_sString[i] + 32);
		else result += p_sString[i];
	}

	return result;
}

VOID Utils::ErrorExit(char* msg)
{
	FILE* f;

	fopen_s(&f, "Jamoa.log", "a+");

	if (f != 0)
	{
		fprintf(f, "%s\n", msg);
		fclose(f);
	}

	ExitProcess(0);
}

INT Utils::Guard_strcmp(LPCSTR p1, LPCSTR p2)
{
	LPCSTR s1 = p1;
	LPCSTR s2 = p2;
	CHAR c1, c2;
	do
	{
		c1 = *s1++;
		c2 = *s2++;
		if (c1 == '\0')
			return c1 - c2;
	} while (c1 == c2);
	return c1 - c2;
}

LPSTR Utils::Guard_strcat(LPSTR s1, LPCSTR s2)
{
	LPSTR cp = s1;
	while (*cp != '\0')
		cp++;
	while ((*cp++ = *s2++) != '\0');

	return (s1);
}

LPCWSTR Utils::Guard_wcsistr(LPCWSTR s1, LPCWSTR s2)
{
	if (s1 && s2)
	{
		LPCWSTR s;
		LPCWSTR sub;
		for (; *s1; s1++)
		{
			for (sub = s2, s = s1; *sub && *s; sub++, s++)
			{
				WCHAR ms, msub;
				if (*s >= 'a' && *s <= 'z')	ms = *s - 0x20;
				else						ms = *s;
				if (*sub >= 'a' && *sub <= 'z') msub = *sub - 0x20;
				else							msub = *sub;
				if (ms != msub) break;
			}

			if (!*sub)
				return s1;
		}
	}
	return NULL;
}

LPWSTR Utils::Guard_wcscpy(LPWSTR s1, LPCWSTR s2)
{
	LPWSTR cp = s1;
	while ((*cp++ = *s2++) != L'\0');

	return (s1);
}

LPWSTR Utils::Guard_wcscat(LPWSTR s1, LPCWSTR s2)
{
	LPWSTR cp = s1;
	while (*cp != L'\0')
		cp++;
	while ((*cp++ = *s2++) != L'\0');

	return (s1);
}