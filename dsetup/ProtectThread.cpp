#include "stdafx.h"
#include <stdio.h>
#include <io.h>
#include <string>
#include <iostream>
#include <sstream>
#include <psapi.h>
#include <icmpapi.h>
#include <string>
#include <process.h>
#include <windows.h>

#include "hook.h"
#include "RabbitCipher.h"
//#include "RC4Cipher.h"
#include "cpuutils.h"
#include "process.h"
#include "structs.h"
#include "ProcessGuard.h"
#include "PacketStructs.h"
#include "ThemidaSDK.h"

#include "DiscordSDK.h"

#pragma comment(lib, "psapi.lib")

using namespace std;

typedef int(__fastcall* _AddNetworkQueue) (unsigned int, unsigned int, NetworkPacket*);
_AddNetworkQueue Standard_AddNetworkQueue;

typedef void(__cdecl* _SendPacket) (unsigned int, char*, ...);
_SendPacket Standard_SendPacket;

typedef void(__cdecl* _Encrypt) (unsigned char*, __int64*, int);
_Encrypt Standard_Encrypt;

typedef void(__cdecl* _Decrypt) (unsigned char*, __int64*, int);
_Decrypt Standard_Decrypt;

typedef char(__fastcall* _Standard_ChangePrivateKey) (unsigned int, unsigned int, struct NetworkPacket*);
_Standard_ChangePrivateKey Standard_ChangePrivateKey;

typedef void(_fastcall* _MasterProcessPreRender) (unsigned int, unsigned int, unsigned int);
_MasterProcessPreRender Standard_MasterProcessPreRender;

typedef int(_fastcall* _DrawTextTTFToCanvas) (unsigned int, unsigned int, int, int, wchar_t*, FontDrawInfo*, unsigned char, int, int, unsigned int);
_DrawTextTTFToCanvas Standard_DrawTextTTFToCanvas;

typedef void(_fastcall* _Render) (unsigned int, unsigned int, unsigned int FRenderInterface);
_Render Standard_Render;

BOOL discordInitialized = false;
DISCORD_APPLICATION dApp;
DiscordActivity activity;
DiscordCreateParams params;
DiscordActivityAssets assets;
DiscordActivityTimestamps timestamps;

time_t startUsingTime;

SpecialString specialString;

BOOL keyInitialized = false;
BOOL worldKeyInitialized = false;
BOOL inWorldState = false;
BOOL inPrepareWorldState = false;
BOOL inLogoutState = false;
BOOL inLobbyState = false;
BOOL inAuthState = true;
BOOL guardLogThreadStarted = false;

unsigned int Canvas;
unsigned int hEngineStart, hEngineEnd;
unsigned int mainThread;
unsigned int sndAddr;
unsigned int lastPing = 1;

RabbitCipher* mainInCipher = new RabbitCipher();
RabbitCipher* mainOutCipher = new RabbitCipher();

RabbitCipher* worldInCipher = new RabbitCipher();
RabbitCipher* worldOutCipher = new RabbitCipher();

static CRITICAL_SECTION cipherSection;

DWORD WINAPI InitThread(LPVOID lpParameter)
{
	MUTATE_START

	HMODULE engineHandler = GetModuleHandleA("engine.dll");

	MODULEINFO modinfo;
	GetModuleInformation(GetCurrentProcess(), engineHandler, &modinfo, sizeof(MODULEINFO));

	hEngineStart = (unsigned int) engineHandler;
	hEngineEnd = hEngineStart + modinfo.SizeOfImage - 1;

	if (engineHandler == 0 || modinfo.SizeOfImage == 0)
	{
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
		printf("[ERROR] Cannot get Engine section!\r\n");
#else
		Utils::ErrorExit("[ERROR] 0x00001\r\n");
#endif
		return false;
	}

	ADDRESS_VALUE pAddNetworkQueue = Process::SearchSignature((void*)engineHandler, modinfo.SizeOfImage, (void*)AddNetworkQueueSignature, sizeof(AddNetworkQueueSignature));
	if (pAddNetworkQueue == 0)
	{
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
		printf("[ERROR] Cannot get Engine pAddNetworkQueue!\r\n");
#else
		Utils::ErrorExit("[ERROR] 0x00002\r\n");
#endif
		return false;
	}

#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
	printf("AddNetworkQueueAddr %d\r\n", pAddNetworkQueue);
#endif

	Standard_AddNetworkQueue = (_AddNetworkQueue) splice((unsigned char*)pAddNetworkQueue, NewAddNetworkQueue);

	ADDRESS_VALUE pSendPacket = Process::SearchSignature((void*)engineHandler, modinfo.SizeOfImage, (void*)SendPacketSignature, sizeof(SendPacketSignature));
	if (pSendPacket == 0)
	{
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
		printf("[ERROR] Cannot get Engine pSendPacket!\r\n");
#else
		Utils::ErrorExit("[ERROR] 0x00004\r\n");
#endif
		return false;
	}

#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
	printf("SendPacketAddr %d\r\n", pSendPacket);
#endif

	Standard_SendPacket = (_SendPacket) splice((unsigned char*)pSendPacket, NewSendPacket);

	ADDRESS_VALUE pEncryptRaw = Process::SearchSignature((void*)engineHandler, modinfo.SizeOfImage, (void*)EncryptRawSignature, sizeof(EncryptRawSignature));
	if (pEncryptRaw == 0)
	{
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
		printf("[ERROR] Cannot get Engine pEncryptRaw!\r\n");
#else
		Utils::ErrorExit("[ERROR] 0x00008\r\n");
#endif
		return false;
	}

	Standard_Encrypt = (_Encrypt)splice((unsigned char*)pEncryptRaw, NewEncryptMethod);

	ADDRESS_VALUE pDecryptRaw = Process::SearchSignature((void*)engineHandler, modinfo.SizeOfImage, (void*)DecryptRawSignature, sizeof(DecryptRawSignature));
	if (pDecryptRaw == 0)
	{
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
		printf("[ERROR] Cannot get Engine pDecryptRaw!\r\n");
#else
		Utils::ErrorExit("[ERROR] 0x000016\r\n");
#endif
		return false;
	}

	Standard_Decrypt = (_Decrypt)splice((unsigned char*)pDecryptRaw, NewDecryptMethod);

	ADDRESS_VALUE pNewChangeKeyRaw = Process::SearchSignature((void*)engineHandler, modinfo.SizeOfImage, (void*)ChangePrivateKeySignature, sizeof(ChangePrivateKeySignature));
	if (pNewChangeKeyRaw == 0)
	{
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
		printf("[ERROR] Cannot get Engine pNewChangeKeyRaw!\r\n");
#else
		Utils::ErrorExit("[ERROR] 0x000032\r\n");
#endif
		return false;
	}

	Standard_ChangePrivateKey = (_Standard_ChangePrivateKey)splice((unsigned char*)pNewChangeKeyRaw, NewChangePrivateKey);

	FARPROC drawTextAddr = GetProcAddress(engineHandler, "?DrawTextTTFToCanvas@UCanvas@@QAEHHHPB_WPBVFontDrawInfo@@EHHPBV?$TArray@PAVFontDrawInfoSection@@@@PAH@Z");
	if (drawTextAddr == 0) {
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
		printf("[ERROR] Cannot get Engine DrawTextTTFToCanvas!\r\n");
#else
		Utils::ErrorExit("[ERROR] 0x000064\r\n");
#endif
		return false;
	}

	Standard_DrawTextTTFToCanvas = (_DrawTextTTFToCanvas)drawTextAddr;

	FARPROC masterProcRenderAddr = GetProcAddress(engineHandler, "?MasterProcessPreRender@UInteractionMaster@@QAEXPAVUCanvas@@@Z");
	if (masterProcRenderAddr == 0) {
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
		printf("[ERROR] Cannot get Engine MasterProcessPreRender!\r\n");
#else
		Utils::ErrorExit("[ERROR] 0x0000128\r\n");
#endif
		return false;
	}

	Standard_MasterProcessPreRender = (_MasterProcessPreRender)splice((unsigned char*) masterProcRenderAddr, NewMasterProcessPreRender);

	FARPROC renderAddr = GetProcAddress(engineHandler, "?Render@FPlayerSceneNode@@UAEXPAVFRenderInterface@@@Z");
	if (renderAddr == 0) {
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
		printf("[ERROR] Cannot get Engine FPlayerSceneNode!\r\n");
#else
		Utils::ErrorExit("[ERROR] 0x0000256\r\n");
#endif
		return false;
	}

	Standard_Render = (_Render) splice((unsigned char*) renderAddr, NewRender);

	InitializeCriticalSection(&cipherSection);

#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
	printf("Hooks Complete\r\n");
#endif

	DWORD dbgCheckFlag;
	CHECK_DEBUGGER(dbgCheckFlag, 0x12345678);
	if (dbgCheckFlag != 0x12345678) {
		Utils::ErrorExit("[ERROR] -1\r\n");
		return false;
	}

	DWORD vmCheckFlag;
	CHECK_VIRTUAL_PC(vmCheckFlag, 0x12345678);
	if (vmCheckFlag != 0x12345678) {
		Utils::ErrorExit("[ERROR] -2\r\n");
		return false;
	}

	MUTATE_END
	return true;
}

char __fastcall NewChangePrivateKey(unsigned int This, unsigned int EDX, struct NetworkPacket* packet)
{
	DWORD dbgCheckFlag;
	CHECK_DEBUGGER(dbgCheckFlag, 0x12345678);
	if (dbgCheckFlag != 0x12345678) {
		Utils::ErrorExit("[ERROR] -1\r\n");
		return false;
	}

	DWORD vmCheckFlag;
	CHECK_VIRTUAL_PC(vmCheckFlag, 0x12345678);
	if (vmCheckFlag != 0x12345678) {
		Utils::ErrorExit("[ERROR] -2\r\n");
		return false;
	}

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
	printf("Call NewChangePrivateKey args edx %d, id %d subid %d\r\n", This, packet->id, packet->subid);
#endif

	if (packet->id == 0xFE && packet->subid == 0x138)
	{
		if (inPrepareWorldState)
		{
			EnterCriticalSection(&cipherSection);

			VM_START_WITHLEVEL(19)

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
			printf("Received World Enter key - %02x:%02x\r\n", packet->id, packet->subid);
#endif

			if (worldInCipher != NULL) {
				delete worldInCipher;
				worldInCipher = NULL;
			}
			
			if (worldOutCipher != NULL) {
				delete worldOutCipher;
				worldOutCipher = NULL;
			}

			worldInCipher = new RabbitCipher();
			worldOutCipher = new RabbitCipher();

			wchar_t MAC[1024];
			memset(MAC, 0, 1024 * 2);

			if (!CpuUtils::GetMAC(MAC))
			{
				Utils::ErrorExit("[ERROR] 0x10004001!");
				return 0;
			}

			if (wcslen(MAC) < 8)
			{
				Utils::ErrorExit("[ERROR] 0x10004002!");
				return 0;
			}

			worldInCipher->setup_key((uint8_t*)packet->data + 4);
			worldOutCipher->setup_key((uint8_t*)packet->data + 4);

			worldInCipher->load_iv(MAC);
			worldOutCipher->load_iv(MAC);

			inPrepareWorldState = false;
			worldKeyInitialized = true;
			inWorldState = true;

			VM_END

			LeaveCriticalSection(&cipherSection);
		}
	}

	return Standard_ChangePrivateKey(This, EDX, packet);
}

void __stdcall NewEncryptMethod(unsigned char* raw, __int64* key, int size)
{
	__try
	{
		if (inPrepareWorldState) {
			EnterCriticalSection(&cipherSection);

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
			printf("[ENCRYPT] Enter lock section\r\n");
#endif
		}

		if (inWorldState)
		{
			if (worldKeyInitialized)
			{
				encrypt(1, raw, key, size);

				if (inLogoutState)
				{
					logout();
				}
			}

			return;
		}

		if (keyInitialized)
		{
			encrypt(0, raw, key, size);

			if (inLogoutState)
			{
				logout();
			}
			return;
		}
	}
	__finally
	{
		if (inPrepareWorldState) {
			LeaveCriticalSection(&cipherSection);

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
			printf("[ENCRYPT] Leave lock section\r\n");
#endif
		}
	}

}

void __stdcall NewDecryptMethod(unsigned char* raw, __int64* key, int size)
{
	__try
	{
		if (inPrepareWorldState) 
		{
			EnterCriticalSection(&cipherSection);

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
			printf("[DECRYPT] Enter lock section\r\n");
#endif
		}

		if (inWorldState)
		{
			if (worldKeyInitialized)
			{
				decrypt(1, raw, key, size);
			}

			return;
		}

		if (keyInitialized)
		{
			decrypt(0, raw, key, size);
			return;
		}
	}
	__finally
	{
		if (inPrepareWorldState) 
		{
			LeaveCriticalSection(&cipherSection);
#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
			printf("[DECRYPT] Leave lock section\r\n");
#endif
		}
	}
}

void __stdcall logout()
{
	if (mainInCipher != NULL) {
		delete mainInCipher;
		mainInCipher = NULL;
	}

	if (mainOutCipher != NULL) {
		delete mainOutCipher;
		mainOutCipher = NULL;
	}

	if (worldInCipher != NULL) {
		delete worldInCipher;
		worldInCipher = NULL;
	}

	if (worldOutCipher != NULL) {
		delete worldOutCipher;
		worldOutCipher = NULL;
	}
	
	inLogoutState = false;
	inWorldState = false;
	inPrepareWorldState = false;
	worldKeyInitialized = false;
	keyInitialized = false;
}

void __stdcall encrypt(int action, unsigned char* raw, __int64* key, int size)
{
#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
	printf("Encrypt action = %d [", action);

	for (int i = 0; i < sizeof(raw); i++)
	{
		printf(" %02X", raw[i]);
	}

	printf("]\r\n");
#endif

	if (action == 1)
	{
		worldOutCipher->process(raw, size);
	}
	else
	{
		mainOutCipher->process(raw, size);
	}
}

void __stdcall decrypt(int action, unsigned char* raw, __int64* key, int size)
{
	if (action == 1)
	{
		worldInCipher->process(raw, size);
	}
	else
	{
		mainInCipher->process(raw, size);
	}
	
#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
	printf("Decrypt action = %d [", action);

	for (int i = 0; i < sizeof(raw); i++)
	{
		printf(" %02X", raw[i]);
	}

	printf("]\r\n");
#endif
}

int __fastcall NewAddNetworkQueue(unsigned int This, unsigned int EDX, struct NetworkPacket * packet)
{
	BOOL oldEnterWorldState = inPrepareWorldState;
	if (inPrepareWorldState) {
		EnterCriticalSection(&cipherSection);

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
		printf("[AddNetQueue] Enter lock section\r\n");
#endif
	}

	__try
	{
		BOOL needReHandle = HandleReceive(packet);
		if (needReHandle) {
			return Standard_AddNetworkQueue(This, EDX, packet);
		}

		return 1;
	}
	__finally
	{
		if (oldEnterWorldState) {
			LeaveCriticalSection(&cipherSection);

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
			printf("[AddNetQueue] Leave lock section\r\n");
#endif
		}
	}
}

void GuardLogNotificationStart() 
{
	MUTATE_START

	if (guardLogThreadStarted) {
		return;
	}

	guardLogThreadStarted = true;

	_beginthread(StartGuardLogNotificationThread, 0, NULL);
	CloseHandle(StartGuardLogNotificationThread);

	MUTATE_END
}

void StartGuardLogNotificationThread(void* param) 
{
	while (true)
	{
		if (sndAddr != 0 && (inLobbyState == true || inWorldState == true))
		{
			SendGuardLogNotification();
			CloseHandle(StartGuardLogNotificationThread);
		}

		Sleep(15000);
	}

	_beginthread(StartGuardLogNotificationThread, 0, NULL);
	CloseHandle(StartGuardLogNotificationThread);
}

//void __cdecl SendTestIllegalFormatPacket(char* format) {
//	SystemSendPacket("chS", GUARD_OPCODE, UNK_FORMAT_OPCODE, (wchar_t*) format);
//}

void SendGuardLogNotification() 
{
	MUTATE_START

	unsigned char guardData[20480];

	unsigned int size = Guard_FlushQueue(guardData);
	if (guardData && size != -1) {
		SystemSendPacket("chb", GUARD_OPCODE, PR_INJ_LIST_OPCODE, (unsigned int) size, (void*) guardData);
	}

	MUTATE_END
}

BOOL _fastcall HandleReceive(struct NetworkPacket* packet)
{
	if (packet->subid == 0xFFFF)
	{
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
		printf("Received Normal Packet - 0x00:%02x\r\n", packet->id);
#endif
		switch (packet->id)
		{
			case 0x09:
			{
				MUTATE_START

				inLobbyState = true;

				if (!guardLogThreadStarted) {
					GuardLogNotificationStart();
				}

				MUTATE_END
				return true;
			}
			case 0x2E:
			{
				VM_START_WITHLEVEL(19)

				inAuthState = false;

#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
				printf("Received PV key - %02x:%02x\r\n", packet->subid, packet->id);
#endif

				if (mainInCipher != NULL)
				{
					delete mainInCipher;
					mainInCipher = NULL;
				}
				
				if (mainOutCipher != NULL)
				{
					delete mainOutCipher;
					mainOutCipher = NULL;
				}
				
				mainInCipher = new RabbitCipher();
				mainOutCipher = new RabbitCipher();

				wchar_t MAC[1024];
				memset(MAC, 0, 1024 * 2);

				if (!CpuUtils::GetMAC(MAC))
				{
					Utils::ErrorExit("[ERROR] 0x10002001!");
					return;
				}

				if (wcslen(MAC) < 8)
				{
					Utils::ErrorExit("[ERROR] 0x10002002!");
					return;
				}

				mainInCipher->setup_key((uint8_t*) packet->data + 1);
				mainOutCipher->setup_key((uint8_t*) packet->data + 1);
			
				mainInCipher->load_iv(MAC);
				mainOutCipher->load_iv(MAC);

				VM_END;

				keyInitialized = true;
				inWorldState = false;

				return true;
			}
		}
	}
	else if (packet->id == 0xFE)
	{
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
		printf("Received FE Packet - %02x:%02x\r\n", packet->id, packet->subid);
#endif
		switch (packet->subid)
		{
			case 0xB7: 
			{
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
				printf("Received World Reserve Result - %02x:%02x\r\n", packet->id, packet->subid);
#endif
				inWorldState = false;
				inPrepareWorldState = true;
				return true;
			}
			case 0x1C7:
			{
				inLobbyState = true;
				return true;
			}
			case 0xB9:
			{
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
				printf("Received World Server Exit - %02x:%02x\r\n", packet->id, packet->subid);
#endif
				return true;
			}
			case 0x2711: // discord precense
			{
#if OPT_ENABLED(OPT_DISCORD_EVENTS_LOG)
				printf("Received discord presence packet\r\n");
#endif
				ExDiscordPrecense nPacket;
				nPacket.Decode((unsigned char*) packet->data);
				
				InitOrUpdateDiscordActivity(
					nPacket.applicationId,
					nPacket.activityDetail,
					nPacket.activityState,
					nPacket.largeImageCode,
					nPacket.largeText,
					nPacket.smallText
				);
				return false;
			}
		}
	}
	else if (packet->id == 0x00) // Auth branch
	{
		inAuthState = true;
		return true;
	}

	return true;
}

void __cdecl SystemSendPacket(char* format, ...)
{
	if (sndAddr == 0)
	{
		return;
	}

	unsigned char buf[20480];
	int size = 0, len;
	wchar_t* wstr;
	va_list args;
	va_start(args, format);

	while (*format != 0)
	{
		switch (*format)
		{
		case 'c':
			*(unsigned char*)(buf + size) = va_arg(args, unsigned char);
			size++;
			break;
		case 'h':
			*(unsigned short int*) (buf + size) = va_arg(args, unsigned short int);
			size += 2;
			break;
		case 'd':
			*(unsigned int*)(buf + size) = va_arg(args, unsigned int);
			size += 4;
			break;
		case 'Q':
			*(unsigned __int64*)(buf + size) = va_arg(args, unsigned __int64);
			size += 8;
			break;
		case 'b':
			len = va_arg(args, unsigned int);
			memcpy(buf + size, va_arg(args, void*), len);
			size += len;
			break;
		case 's':
		case 'S':
			wstr = va_arg(args, wchar_t*);
			if (wstr == 0)
			{
				len = 2;
				*(unsigned short int*) (buf + size) = 0;
			}
			else
			{
#if OPT_ENABLED(OPT_SEND_STRINGS_LOG)
				printf("Send str %s\r\n", wstr);
#endif

				len = wcslen(wstr) * 2 + 2;
				memcpy(buf + size, wstr, len);
			}
			size += len;
			break;
		default:
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
			printf("Unknown format %s\r\n", *format);
#endif
			SystemSendPacket("chS", GUARD_OPCODE, UNK_FORMAT_OPCODE, *format);
			break;
		}
		format++;
	}

	va_end(args);

#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
	if (buf[0] == 0xD0)
	{
		uint16_t nextOpcode;
		nextOpcode = buf[1];

		printf("Sent packet id: %02x exId %02x format %s\r\n", buf[0], nextOpcode, format);
	}
	else
	{
		printf("Sent packet id: %02x format %s\r\n", buf[0], format);
	}
#endif

	Standard_SendPacket(sndAddr, "b", size, (int)buf);
}

void __cdecl NewSendPacket(unsigned int object, char* format, ...)
{
	unsigned int retAddr = *((unsigned int*)&object - 1);

	if (sndAddr == 0) 
	{
		sndAddr = object;
	}

	if (sndAddr == 0) 
	{
		return;
	}

	if ((retAddr < hEngineStart) || (retAddr > hEngineEnd))
	{
		SystemSendPacket("chd", GUARD_OPCODE, NO_TRUSTED_CALL_OPCODE, 0x01);
		Utils::ErrorExit("[ERROR] 0x0000512!");
		return;
	}

	if (GetCurrentThreadId() != mainThread)
	{
		SystemSendPacket("chd", GUARD_OPCODE, NO_TRUSTED_CALL_OPCODE, 0x02);
		Utils::ErrorExit("[ERROR] 0x00001024!");
		return;
	}

	unsigned char buf[10240];
	int size = 0, len;
	wchar_t* wstr;
	va_list args;
	va_start(args, format);

	while (*format != 0)
	{
		switch (*format)
		{
			case 'c':
				*(unsigned char*)(buf + size) = va_arg(args, unsigned char);
				size++;
				break;
			case 'h':
				*(unsigned short int*) (buf + size) = va_arg(args, unsigned short int);
				size += 2;
				break;
			case 'd':
				*(unsigned int*)(buf + size) = va_arg(args, unsigned int);
				size += 4;
				break;
			case 'Q':
				*(unsigned __int64*)(buf + size) = va_arg(args, unsigned __int64);
				size += 8;
				break;
			case 'b':
				len = va_arg(args, unsigned int);
				memcpy(buf + size, va_arg(args, void*), len);
				size += len;
				break;
			case 's':
			case 'S':
				wstr = va_arg(args, wchar_t*);
				if (wstr == 0)
				{
					len = 2;
					*(unsigned short int*) (buf + size) = 0;
				}
				else
				{
#if OPT_ENABLED(OPT_SEND_STRINGS_LOG)
					printf("Send str %s\r\n", wstr);
#endif
					len = wcslen(wstr) * 2 + 2;
					memcpy(buf + size, wstr, len);
				}
				size += len;
				break;
			default:
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
				printf("Unknown format %s\r\n", *format);
#endif
				SystemSendPacket("chS", GUARD_OPCODE, UNK_FORMAT_OPCODE, *format);
				break;
		}
		format++;
	}

	va_end(args);

#if OPT_ENABLED(OPT_OPCODE_PRINT_LOG)
	if (buf[0] == 0xD0)
	{
		uint16_t nextOpcode;
		nextOpcode = buf[1];

		printf("Sent packet id: %02x exId %02x format %s\r\n", buf[0], nextOpcode, format);
	}
	else
	{
		printf("Sent packet id: %02x format %s\r\n", buf[0], format);
	}
#endif

	switch (buf[0])
	{
		case 0xD0:
		{
			uint16_t nextOpcode;
			nextOpcode = buf[1];

			switch (nextOpcode)
			{
				case 0x70:
				{
					MUTATE_START

					wchar_t serialNumber[1024], MAC[1024], HwGuid[1024];
					memset(serialNumber, 0, 1024 * 2);
					memset(MAC, 0, 1024 * 2);

					if (!CpuUtils::GetPhysDriveSerialNumber(serialNumber))
					{
						SystemSendPacket("ch", GUARD_OPCODE, UNDEFINED_CPU_CALL_OPCODE);
						Utils::ErrorExit("[ERROR] 0x10000000!");
						return;
					}

					if (!CpuUtils::GetMAC(MAC))
					{
						SystemSendPacket("ch", GUARD_OPCODE, UNDEFINED_CPU_CALL_OPCODE);
						Utils::ErrorExit("[ERROR] 0x10000001!");
						return;
					}

					if (!CpuUtils::getHwUUID(HwGuid))
					{
						SystemSendPacket("ch", GUARD_OPCODE, UNDEFINED_CPU_CALL_OPCODE);
						Utils::ErrorExit("[ERROR] 0x10000002!");
						return;
					}

					if ((wcslen(MAC) == 0) || (wcslen(serialNumber) == 0) || (wcslen(HwGuid) == 0))
					{
						SystemSendPacket("ch", GUARD_OPCODE, UNDEFINED_CPU_CALL_OPCODE);
						Utils::ErrorExit("[ERROR] 0x10000003!");
						return;
					}

#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
					printf("Serial num length: + %d\r\n", wcslen(serialNumber));
					printf("MAC num length: + %d\r\n", wcslen(MAC));
					printf("HWID num length: + %d\r\n", wcslen(HwGuid));
#endif

					memcpy(buf + size, serialNumber, wcslen(serialNumber) * 2 + 2);
					size += wcslen(serialNumber) * 2 + 2;
					memcpy(buf + size, MAC, wcslen(MAC) * 2 + 2);
					size += wcslen(MAC) * 2 + 2;
					memcpy(buf + size, HwGuid, wcslen(HwGuid) * 2 + 2);
					size += wcslen(HwGuid) * 2 + 2;

					MUTATE_END
					break;
				}
				case 0x71:
				{
#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
					printf("Sent return from world server\r\n");
#endif
					if (worldInCipher != NULL)
					{
						delete worldInCipher;
						worldInCipher = NULL;
					}

					if (worldOutCipher != NULL)
					{
						delete worldOutCipher;
						worldOutCipher = NULL;
					}

					worldInCipher = new RabbitCipher();
					worldOutCipher = new RabbitCipher();

					inPrepareWorldState = false;
					worldKeyInitialized = false;
					inWorldState = false;
					keyInitialized = true;

					break;
				}
			}
			break;
		}
		case 0x00:
		{
#if OPT_ENABLED(OPT_OPCODE_PRINT_LOG)
			printf("Sent logout\r\n");
#endif
			if (inAuthState)
			{
#if OPT_ENABLED(OPT_OPCODE_PRINT_LOG)
				printf("Remove from auth\r\n");
#endif
				Standard_SendPacket(object, "b", size, (int)buf);
				logout();

				return;
			}
			else
			{
				inLogoutState = true;
			}
			break;
		}
		case 0x0E:
		{
			MUTATE_START

			wchar_t serialNumber[1024], MAC[1024], HwGuid[1024];
			memset(serialNumber, 0, 1024 * 2);
			memset(MAC, 0, 1024 * 2);

			if (!CpuUtils::GetPhysDriveSerialNumber(serialNumber))
			{
				SystemSendPacket("ch", GUARD_OPCODE, UNDEFINED_CPU_CALL_OPCODE);
				Utils::ErrorExit("[ERROR] 0x10000000!");
				return;
			}

			if (!CpuUtils::GetMAC(MAC))
			{
				SystemSendPacket("ch", GUARD_OPCODE, UNDEFINED_CPU_CALL_OPCODE);
				Utils::ErrorExit("[ERROR] 0x10000001!");
				return;
			}

			if (!CpuUtils::getHwUUID(HwGuid))
			{
				SystemSendPacket("ch", GUARD_OPCODE, UNDEFINED_CPU_CALL_OPCODE);
				Utils::ErrorExit("[ERROR] 0x10000002!");
				return;
			}

			if ((wcslen(MAC) == 0) || (wcslen(serialNumber) == 0) || (wcslen(HwGuid) == 0))
			{
				SystemSendPacket("ch", GUARD_OPCODE, UNDEFINED_CPU_CALL_OPCODE);
				Utils::ErrorExit("[ERROR] 0x10000003!");
				return;
			}

#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
			printf("Serial num length: + %d\r\n", wcslen(serialNumber));
			printf("MAC num length: + %d\r\n", wcslen(MAC));
			printf("HWID num length: + %d\r\n", wcslen(HwGuid));
#endif

			memcpy(buf + size, serialNumber, wcslen(serialNumber) * 2 + 2);
			size += wcslen(serialNumber) * 2 + 2;
			memcpy(buf + size, MAC, wcslen(MAC) * 2 + 2);
			size += wcslen(MAC) * 2 + 2;
			memcpy(buf + size, HwGuid, wcslen(HwGuid) * 2 + 2);
			size += wcslen(HwGuid) * 2 + 2;

			MUTATE_END

			break;
		}
	}

	Standard_SendPacket(object, "b", size, (int)buf);
}

void _fastcall NewMasterProcessPreRender(unsigned int This, unsigned int EDX, unsigned int UCanvas)
{
	Canvas = UCanvas;

	if (!specialString.isDraw)
	{
		specialString.isDraw = true;
		specialString.x = 270;
		specialString.y = 30;
		specialString.FontDrawInfo.color = 0xFF00FF00;
		specialString.FontDrawInfo.font = -1;
		wcscpy_s(specialString.text, (wchar_t*) L"Jamoa Games");
	}

	Standard_MasterProcessPreRender(This, EDX, UCanvas);
}

void _fastcall NewRender(unsigned int This, unsigned int EDX, unsigned int FRenderInterface)
{
	mainThread = GetCurrentThreadId();

	RECT L2Rect;
	HWND* L2hWND = (HWND*)GetProcAddress(LoadLibraryA("core.dll"), "?GTopWnd@@3PAUHWND__@@A");

	GetClientRect(*L2hWND, &L2Rect);
	Standard_Render(This, EDX, FRenderInterface);
	if (Canvas != 0 && inLobbyState)
		Standard_DrawTextTTFToCanvas(Canvas, 0, L2Rect.right - specialString.x, L2Rect.top + specialString.y, specialString.text, &specialString.FontDrawInfo, 0xFF, 0, 0, 0);
}

VOID InitOrUpdateDiscordActivity(int64_t applicationId, char* activityDetail, char* activityState, char* largeIco, char* largeImageText, char* smallImageText) {
	if (!discordInitialized) {
		discordInitialized = true;

		startUsingTime = time(nullptr);

		DiscordCreateParamsSetDefault(&params);
		params.client_id = applicationId;
		params.flags = DiscordCreateFlags_NoRequireDiscord; // dont force discord to launch
		params.event_data = &dApp;

		// disable integration in case of any error (otherwise your appliction may crash)
		if (DiscordCreate(DISCORD_VERSION, &params, &dApp.core) != DiscordResult_Ok)
		{
			return;
		}

		dApp.users = dApp.core->get_user_manager(dApp.core);
		dApp.activities = dApp.core->get_activity_manager(dApp.core);

		UpdateDiscordActivity(applicationId, activityDetail, activityState, largeIco, largeImageText, smallImageText);

		_beginthread(DiscordCheckState, 0, NULL);
		CloseHandle(DiscordCheckState);
	} 
	else
	{
		UpdateDiscordActivity(applicationId, activityDetail, activityState, largeIco, largeImageText, smallImageText);
	}
}

VOID DiscordCheckState(void* param) {
	while (true)
	{
		if (dApp.core->run_callbacks(dApp.core) != DiscordResult_Ok)
		{
			return;
		}

		Sleep(1000);
	}

	_beginthread(DiscordCheckState, 0, NULL);
	CloseHandle(DiscordCheckState);
}

VOID UpdateDiscordActivity(int64_t applicationId, char* activityDetail, char* activityState, char* largeIco, char* largeImageText, char* smallImageText)
{
	activity.type = DiscordActivityType_Playing;
	activity.application_id = applicationId;

	sprintf(activity.details, (char*)activityDetail);
	sprintf(activity.state, (char*)activityState);

	sprintf(assets.large_image, (char*) largeIco);
	sprintf(assets.large_text, (char*)largeImageText);
	sprintf(assets.small_image, "");
	sprintf(assets.small_text, (char*)smallImageText);

#if OPT_ENABLED(OPT_DISCORD_EVENTS_LOG)
	printf("Discord applicationId - %I64d\r\n", activity.application_id);
	printf("Discord activity - %s\r\n", activity.details);
	printf("Discord state - %s\r\n", activity.state);
	printf("Discord large img text - %s\r\n", assets.large_text);
	printf("Discord short img text - %s\r\n", assets.small_text);
#endif

	activity.assets = assets;

	time_t endUsingTime = time(nullptr);
	timestamps.start = (int64_t)(endUsingTime - startUsingTime);

	activity.timestamps = timestamps;

	dApp.activities->update_activity(dApp.activities, &activity, nullptr, nullptr);
}