#pragma once

#define GUARD_OPCODE					(uint8_t) 0xCB & 0xFF
#define PR_INJ_LIST_OPCODE				(uint16_t) 0xBE & 0xFFFF
#define UNK_FORMAT_OPCODE				(uint16_t) 0xBF & 0xFFFF
#define NO_TRUSTED_CALL_OPCODE			(uint16_t) 0xC0 & 0xFFFF
#define UNDEFINED_CPU_CALL_OPCODE		(uint16_t) 0xC1 & 0xFFFF

DWORD WINAPI InitThread(LPVOID lpParameter);

void __cdecl SystemSendPacket(char*, ...);
void __cdecl NewSendPacket(unsigned int, char*, ...);

void __stdcall NewEncryptMethod(unsigned char*, __int64*, int);
void __stdcall NewDecryptMethod(unsigned char*, __int64*, int);

char __fastcall NewChangePrivateKey(unsigned int, unsigned int, struct NetworkPacket*);
int __fastcall NewAddNetworkQueue(unsigned int, unsigned int, struct NetworkPacket *);
BOOL _fastcall HandleReceive(struct NetworkPacket *);

void _fastcall NewMasterProcessPreRender(unsigned int, unsigned int, unsigned int);
void _fastcall NewRender(unsigned int, unsigned int, unsigned int);

void __stdcall logout();
void __stdcall encrypt(int, unsigned char*, __int64*, int);
void __stdcall decrypt(int, unsigned char*, __int64*, int);

void GuardLogNotificationStart();
void StartGuardLogNotificationThread(void*);
void SendGuardLogNotification();

VOID InitOrUpdateDiscordActivity(int64_t, char*, char*, char*, char*, char*);
VOID DiscordCheckState(void*);
VOID UpdateDiscordActivity(int64_t, char*, char*, char*, char*, char*);
