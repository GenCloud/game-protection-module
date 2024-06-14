#pragma once
class CpuUtils
{
public:
	static bool GetPhysDriveSerialNumber(wchar_t*);
	static bool getHwUUID(wchar_t*);
	static bool GetMAC(wchar_t*);
	static bool getHWID(wchar_t*);

	static char* flipAndCodeBytes(const char*, int, int, char*);
};

