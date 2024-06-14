#pragma once

#include <stdio.h>
#include <io.h>
#include <string>
#include <cstdint>

char* WStrToCharStr(wchar_t* in) {
	wchar_t str[64];
	wcscpy_s(str, in);

	char* largeText = new char[wcslen(str) + 1];
	wcstombs_s(NULL, largeText, wcslen(str) + 1, str, wcslen(str) + 1);

	return largeText;
}

int WstrLength(wchar_t* str) {
	return wcslen(str) * 2 + 2;
}

typedef struct _ExDiscordPrecense
{
	uint64_t applicationId;
	char* activityDetail;
	char* activityState;
	char* largeImageCode;
	char* largeText;
	char* smallText;

	void Decode(unsigned char* data)
	{
		unsigned char* buf = data;

		int offset = 0;
		applicationId = *(uint64_t*)(buf + offset);
		offset += 8;

		// details
		activityDetail = WStrToCharStr((wchar_t*)(buf + offset));
		offset += WstrLength((wchar_t*)(buf + offset));

		// state
		activityState = WStrToCharStr((wchar_t*)(buf + offset));
		offset += WstrLength((wchar_t*)(buf + offset));

		// large ico
		largeImageCode = WStrToCharStr((wchar_t*)(buf + offset));
		offset += WstrLength((wchar_t*)(buf + offset));

		// large
		largeText = WStrToCharStr((wchar_t*)(buf + offset));
		offset += WstrLength((wchar_t*)(buf + offset));

		// small
		smallText = WStrToCharStr((wchar_t*)(buf + offset));
		offset += WstrLength((wchar_t*)(buf + offset));
	}
} ExDiscordPrecense;
typedef ExDiscordPrecense* PExDiscordPrecense;