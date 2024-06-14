#include <windows.h>

extern unsigned char AddNetworkQueueSignature[] = {
    0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xBF, 0x87, 0xA0, 0x20, 0x64, 0xA1, '?', '?', '?', '?'
};

extern unsigned char SendPacketSignature[] = {
    0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0xB8, 0x14, 0x80, '?', '?', 0xE8, 0x20, 0xED, 0xF7, 0xFF
};

extern unsigned char DecryptRawSignature[] = {
    0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x0C, 0x83, 0xEC, 0x08, 0xBA, 0x01, '?', '?', '?', 0x8A, 0x40
};

extern unsigned char EncryptRawSignature[] = {
    0x55, 0x8B, 0xEC, 0x8B, 0x55, 0x08, 0x83, 0xEC, 0x08, 0x56, 0x8B, 0x75, 0x0C, 0x57, 0x8B, 0x7D
};

extern unsigned char ChangePrivateKeySignature[] = {
    0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x9C, 0x89, 0xA0, 0x20, 0x64, 0xA1, '?', '?', '?', '?'
};

#pragma once
struct FontDrawInfo
{
    int font;
    unsigned int color, u1, u2, u3, u4;
};

struct NetworkPacket
{
    unsigned char id, p1;
    unsigned short int subid, size, p2;
    unsigned char* data;
};

struct SpecialString
{
    bool isDraw;
    FontDrawInfo FontDrawInfo;
    int x, y;
    wchar_t text[64];
};

#pragma pack(1)
typedef struct _IDENTIFY_DATA
{
    USHORT GeneralConfiguration;
    USHORT NumberOfCylinders;
    USHORT Reserved1;
    USHORT NumberOfHeads;
    USHORT UnformattedBytesPerTrack;
    USHORT UnformattedBytesPerSector;
    USHORT SectorsPerTrack;
    USHORT VendorUnique1[3];
    USHORT SerialNumber[10];
    USHORT BufferType;
    USHORT BufferSectorSize;
    USHORT NumberOfEccBytes;
    USHORT FirmwareRevision[4];
    USHORT ModelNumber[20];
    UCHAR  MaximumBlockTransfer;
    UCHAR  VendorUnique2;
    USHORT DoubleWordIo;
    USHORT Capabilities;
    USHORT Reserved2;
    UCHAR  VendorUnique3;
    UCHAR  PioCycleTimingMode;
    UCHAR  VendorUnique4;
    UCHAR  DmaCycleTimingMode;
    USHORT TranslationFieldsValid : 1;
    USHORT Reserved3 : 15;
    USHORT NumberOfCurrentCylinders;
    USHORT NumberOfCurrentHeads;
    USHORT CurrentSectorsPerTrack;
    ULONG  CurrentSectorCapacity;
    USHORT CurrentMultiSectorSetting;
    ULONG  UserAddressableSectors;
    USHORT SingleWordDMASupport : 8;
    USHORT SingleWordDMAActive : 8;
    USHORT MultiWordDMASupport : 8;
    USHORT MultiWordDMAActive : 8;
    USHORT AdvancedPIOModes : 8;
    USHORT Reserved4 : 8;
    USHORT MinimumMWXferCycleTime;
    USHORT RecommendedMWXferCycleTime;
    USHORT MinimumPIOCycleTime;
    USHORT MinimumPIOCycleTimeIORDY;
    USHORT Reserved5[2];
    USHORT ReleaseTimeOverlapped;
    USHORT ReleaseTimeServiceCommand;
    USHORT MajorRevision;
    USHORT MinorRevision;
    USHORT Reserved6[50];
    USHORT SpecialFunctionsEnabled;
    USHORT Reserved7[128];
} IDENTIFY_DATA, * PIDENTIFY_DATA;
#pragma pack()