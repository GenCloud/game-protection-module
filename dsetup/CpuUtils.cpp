#include "stdafx.h"
#include "CpuUtils.h"

//#pragma comment(lib, "iphlpapi.dll")

bool CpuUtils::GetPhysDriveSerialNumber(wchar_t* str)
{
	HANDLE hPhysicalDriveIOCTL = 0;
	char serialNumber[1024], windir[256], filename[256];

	if (GetWindowsDirectoryA(windir, 256) == 0)
		return false;

	memset(filename, 0, 256);

	strcpy_s(filename, "\\\\.\\\\");
	windir[2] = 0;
	strcat_s(filename, windir);

	hPhysicalDriveIOCTL = CreateFileA(filename, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

	if (hPhysicalDriveIOCTL == INVALID_HANDLE_VALUE)
		return false;

	STORAGE_PROPERTY_QUERY query;
	unsigned long cbBytesReturned = 0;
	char buffer[10000];

	memset((void*)&query, 0, sizeof(query));
	query.PropertyId = StorageDeviceProperty;
	query.QueryType = PropertyStandardQuery;

	memset(buffer, 0, sizeof(buffer));

	if (!(DeviceIoControl(hPhysicalDriveIOCTL, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), &buffer, sizeof(buffer), &cbBytesReturned, 0)))
	{
		CloseHandle(hPhysicalDriveIOCTL);
		return false;
	}

	STORAGE_DEVICE_DESCRIPTOR* descrip = (STORAGE_DEVICE_DESCRIPTOR*)&buffer;

	sprintf_s(serialNumber, 1000, "%02X%02X", flipAndCodeBytes(buffer, descrip->SerialNumberOffset, 1, serialNumber));

	mbstowcs_s(0, str, 1000, serialNumber, 1000);

	return true;
}

bool CpuUtils::getHwUUID(wchar_t* str)
{
	HW_PROFILE_INFOA HwProfInfo;
	char HWID[1024];

	if (GetCurrentHwProfileA(&HwProfInfo) == 0)
		return false;

	sprintf_s(HWID, 1000, "%02X%02X", HwProfInfo.szHwProfileGuid);

	mbstowcs_s(0, str, 1000, HWID, 1000);

	return true;
}

bool CpuUtils::getHWID(wchar_t* str)
{
	HW_PROFILE_INFO   HwProfInfo;
	char HWID[1024];

	if (!GetCurrentHwProfile(&HwProfInfo))
	{
		return false;
	}
	sprintf_s(HWID, 1000, "%02X%02X%02X%02X", HwProfInfo.szHwProfileGuid);
	mbstowcs_s(0, str, 1000, HWID, 1000);

	return true;
}

bool CpuUtils::GetMAC(wchar_t* str)
{
	IP_ADAPTER_INFO AdapterInfo[16];
	PIP_ADAPTER_INFO pAdapterInfo;
	unsigned long dwBufLen;
	char MAC[1024];

	dwBufLen = sizeof(AdapterInfo);

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) != ERROR_SUCCESS)
		return false;

	pAdapterInfo = AdapterInfo;

	while ((pAdapterInfo->Address[0] == 0) && (pAdapterInfo->Address[1] == 0) && (pAdapterInfo->Address[2] == 0) && (pAdapterInfo->Address[3] == 0) && (pAdapterInfo->Address[4] == 0) && (pAdapterInfo->Address[5] == 0))
		pAdapterInfo = pAdapterInfo->Next;

	sprintf_s(MAC, 1000, "%02X%02X%02X%02X%02X%02X", pAdapterInfo->Address[0], pAdapterInfo->Address[1], pAdapterInfo->Address[2], pAdapterInfo->Address[3], pAdapterInfo->Address[4], pAdapterInfo->Address[5]);

	mbstowcs_s(0, str, 1000, MAC, 1000);

	return true;
}

char* CpuUtils::flipAndCodeBytes(const char* str, int pos, int flip, char* buf)
{
	int i;
	int j = 0;
	int k = 0;

	buf[0] = '\0';

	if (pos <= 0)
		return buf;

	if (!j)
	{
		char p = 0;

		j = 1;
		k = 0;
		buf[k] = 0;

		for (i = pos; j && str[i] != '\0'; ++i)
		{
			char c = tolower(str[i]);

			if (isspace(c))
				c = '0';

			++p;
			buf[k] <<= 4;

			if (c >= '0' && c <= '9')
				buf[k] |= (unsigned char)(c - '0');
			else if (c >= 'a' && c <= 'f')
				buf[k] |= (unsigned char)(c - 'a' + 10);
			else
			{
				j = 0;
				break;
			}

			if (p == 2)
			{
				if (buf[k] != '\0' && !isprint(buf[k]))
				{
					j = 0;
					break;
				}

				++k;
				p = 0;
				buf[k] = 0;
			}
		}
	}

	if (!j)
	{
		j = 1;
		k = 0;

		for (i = pos; j && str[i] != '\0'; ++i)
		{
			char c = str[i];

			if (!isprint(c))
			{
				j = 0;
				break;
			}

			buf[k++] = c;
		}
	}

	if (!j)
	{
		k = 0;
	}

	buf[k] = '\0';

	if (flip)
		for (j = 0; j < k; j += 2)
		{
			char t = buf[j];
			buf[j] = buf[j + 1];
			buf[j + 1] = t;
		}

	i = j = -1;

	for (k = 0; buf[k] != '\0'; ++k)
	{
		if (!isspace(buf[k]))
		{
			if (i < 0)
				i = k;

			j = k;
		}
	}

	if ((i >= 0) && (j >= 0))
	{
		for (k = i; (k <= j) && (buf[k] != '\0'); ++k)
			buf[k - i] = buf[k];

		buf[k - i] = '\0';
	}

	return buf;
}