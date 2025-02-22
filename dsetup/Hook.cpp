#include "stdafx.h"

__declspec(naked) int __fastcall instruction_length(void* instructionPtr)
{
	__asm
	{
#define DB __asm _emit
		DB 0x60 DB 0x89 DB 0xce DB 0xe8 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0x5d DB 0x83 DB 0xed DB 0x8 DB 0x31 DB 0xc9 DB 0x31 DB 0xc0
		DB 0x31 DB 0xdb DB 0x99 DB 0xac DB 0x88 DB 0xc1 DB 0x3c DB 0xf DB 0x74 DB 0xf DB 0x66 DB 0x81 DB 0x7e DB 0xff DB 0xcd DB 0x20
		DB 0x75 DB 0xa DB 0x46 DB 0xad DB 0xe9 DB 0x1 DB 0x1 DB 0x0 DB 0x0 DB 0xac DB 0xfe DB 0xc4 DB 0xd1 DB 0xe8 DB 0x8a DB 0x84
		DB 0x5 DB 0x41 DB 0x1 DB 0x0 DB 0x0 DB 0x72 DB 0x3 DB 0xc1 DB 0xe8 DB 0x4 DB 0x83 DB 0xe0 DB 0xf DB 0x93 DB 0x80 DB 0xfb
		DB 0xe DB 0xf DB 0x84 DB 0xf2 DB 0x0 DB 0x0 DB 0x0 DB 0x80 DB 0xfb DB 0xf DB 0x74 DB 0x4b DB 0x9 DB 0xdb DB 0xf DB 0x84
		DB 0xd6 DB 0x0 DB 0x0 DB 0x0 DB 0xf DB 0xba DB 0xf3 DB 0x0 DB 0x72 DB 0x5b DB 0xf DB 0xba DB 0xf3 DB 0x1 DB 0xf DB 0x82
		DB 0xc0 DB 0x0 DB 0x0 DB 0x0 DB 0xf DB 0xba DB 0xf3 DB 0x2 DB 0xf DB 0x82 DB 0xb5 DB 0x0 DB 0x0 DB 0x0 DB 0x80 DB 0xe3
		DB 0xf7 DB 0x80 DB 0xf9 DB 0xa0 DB 0x72 DB 0x13 DB 0x80 DB 0xf9 DB 0xa3 DB 0x77 DB 0xe DB 0xf6 DB 0xc5 DB 0x2 DB 0xf DB 0x85
		DB 0x9f DB 0x0 DB 0x0 DB 0x0 DB 0xe9 DB 0x98 DB 0x0 DB 0x0 DB 0x0 DB 0xf6 DB 0xc5 DB 0x1 DB 0xf DB 0x84 DB 0x8f DB 0x0
		DB 0x0 DB 0x0 DB 0xe9 DB 0x8c DB 0x0 DB 0x0 DB 0x0 DB 0x80 DB 0xf9 DB 0x66 DB 0x74 DB 0x11 DB 0x80 DB 0xf9 DB 0x67 DB 0xf
		DB 0x85 DB 0x69 DB 0xff DB 0xff DB 0xff DB 0x80 DB 0xcd DB 0x2 DB 0xe9 DB 0x61 DB 0xff DB 0xff DB 0xff DB 0x80 DB 0xcd DB 0x1
		DB 0xe9 DB 0x59 DB 0xff DB 0xff DB 0xff DB 0xac DB 0x80 DB 0xf9 DB 0xf7 DB 0x74 DB 0x5 DB 0x80 DB 0xf9 DB 0xf6 DB 0x75 DB 0x12
		DB 0xa8 DB 0x38 DB 0x75 DB 0xe DB 0xf6 DB 0xc1 DB 0x1 DB 0x74 DB 0x8 DB 0xf6 DB 0xc5 DB 0x1 DB 0x75 DB 0x2 DB 0x46 DB 0x46
		DB 0x46 DB 0x46 DB 0x89 DB 0xc2 DB 0x24 DB 0x7 DB 0xf6 DB 0xc2 DB 0xc0 DB 0x74 DB 0x13 DB 0xf DB 0x8a DB 0x5d DB 0xff DB 0xff
		DB 0xff DB 0x78 DB 0x32 DB 0xf6 DB 0xc5 DB 0x2 DB 0x75 DB 0x3c DB 0x3c DB 0x4 DB 0x74 DB 0x37 DB 0xeb DB 0x36 DB 0xf6 DB 0xc5
		DB 0x2 DB 0x74 DB 0x9 DB 0x3c DB 0x6 DB 0x74 DB 0x2c DB 0xe9 DB 0x42 DB 0xff DB 0xff DB 0xff DB 0x3c DB 0x4 DB 0x75 DB 0xc
		DB 0xac DB 0x24 DB 0x7 DB 0x3c DB 0x5 DB 0x74 DB 0x1a DB 0xe9 DB 0x32 DB 0xff DB 0xff DB 0xff DB 0x3c DB 0x5 DB 0x74 DB 0x11
		DB 0xe9 DB 0x29 DB 0xff DB 0xff DB 0xff DB 0xf6 DB 0xc5 DB 0x2 DB 0x75 DB 0x9 DB 0x3c DB 0x4 DB 0x74 DB 0x2 DB 0xeb DB 0x1
		DB 0x46 DB 0x46 DB 0x46 DB 0x46 DB 0x46 DB 0xe9 DB 0x14 DB 0xff DB 0xff DB 0xff DB 0x2b DB 0x74 DB 0x24 DB 0x18 DB 0x83 DB 0xfe
		DB 0xf DB 0x77 DB 0x6 DB 0x89 DB 0x74 DB 0x24 DB 0x1c DB 0xeb DB 0x6 DB 0x31 DB 0xc0 DB 0x89 DB 0x44 DB 0x24 DB 0x1c DB 0x61
		DB 0xc3 DB 0x11 DB 0x11 DB 0x28 DB 0x0 DB 0x11 DB 0x11 DB 0x28 DB 0x0 DB 0x11 DB 0x11 DB 0x28 DB 0x0 DB 0x11 DB 0x11 DB 0x28
		DB 0x0 DB 0x11 DB 0x11 DB 0x28 DB 0xf0 DB 0x11 DB 0x11 DB 0x28 DB 0xf0 DB 0x11 DB 0x11 DB 0x28 DB 0xf0 DB 0x11 DB 0x11 DB 0x28
		DB 0xf0 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0x0
		DB 0x0 DB 0x0 DB 0x11 DB 0xff DB 0xff DB 0x89 DB 0x23 DB 0x0 DB 0x0 DB 0x22 DB 0x22 DB 0x22 DB 0x22 DB 0x22 DB 0x22 DB 0x22
		DB 0x22 DB 0x39 DB 0x33 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0xc0 DB 0x0
		DB 0x0 DB 0x88 DB 0x88 DB 0x0 DB 0x0 DB 0x28 DB 0x0 DB 0x0 DB 0x0 DB 0x22 DB 0x22 DB 0x22 DB 0x22 DB 0x88 DB 0x88 DB 0x88
		DB 0x88 DB 0x33 DB 0x40 DB 0x11 DB 0x39 DB 0x60 DB 0x40 DB 0x2 DB 0x0 DB 0x11 DB 0x11 DB 0x22 DB 0x0 DB 0x11 DB 0x11 DB 0x11
		DB 0x11 DB 0x22 DB 0x22 DB 0x22 DB 0x22 DB 0x88 DB 0xc2 DB 0x0 DB 0x0 DB 0xf0 DB 0xff DB 0x0 DB 0x11 DB 0x0 DB 0x0 DB 0x0
		DB 0x11 DB 0x11 DB 0x11 DB 0xe0 DB 0x0 DB 0x0 DB 0xee DB 0xe1 DB 0x3 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x1e DB 0xee DB 0xee
		DB 0xee DB 0x11 DB 0x11 DB 0x1e DB 0x1e DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x0 DB 0x0 DB 0x0 DB 0xee DB 0xee DB 0xee DB 0xee
		DB 0xee DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11
		DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x33 DB 0x33 DB 0x11 DB 0x10 DB 0x11 DB 0x11 DB 0x11
		DB 0x11 DB 0x88 DB 0x88 DB 0x88 DB 0x88 DB 0x88 DB 0x88 DB 0x88 DB 0x88 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11
		DB 0x11 DB 0x0 DB 0x1 DB 0x31 DB 0x11 DB 0x0 DB 0x1 DB 0x31 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0xee DB 0x31 DB 0x11
		DB 0x11 DB 0x11 DB 0x31 DB 0x33 DB 0x31 DB 0x0 DB 0x0 DB 0x0 DB 0x0 DB 0xe1 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11
		DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0xe1 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11 DB 0x11
#undef DB
	}
}

void write_jmp(unsigned char* addr, void* dest)
{
	*addr = 0xE9;

	*(int*)(addr + 1) = (unsigned char*)dest - (addr + 5);
}

int splicing_length(void* codePtr)
{
	int cb = 0;

	do
	{
		cb += instruction_length((char*)codePtr + cb);
	} while (cb < 5);

	return cb;
}

__declspec(align(1)) struct MemBlock
{
	unsigned char mem[28];
	int used;
};

__declspec(naked) int __fastcall try_lock_block(int* used)
{
	__asm
	{
		mov eax, ecx
		xchg[ecx], eax
		ret
	}
}

unsigned char* alloc_rwx_mem()
{
	int nBlocks = 0x1000 / sizeof(MemBlock);

	static MemBlock* first = (MemBlock*)VirtualAlloc(0, sizeof(MemBlock) * nBlocks, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	for (MemBlock* it = first, *last = first + nBlocks; it != last; ++it)
		if (!try_lock_block(&it->used))
			return it->mem;

	return 0;
}

unsigned int splice(unsigned char* addr, void* hook_fn)
{
	unsigned char* saved = alloc_rwx_mem();
	int cb = splicing_length(addr);
	unsigned long oldprotect;

	for (int i = 0; i < cb; i++)
		saved[i] = addr[i];

	write_jmp(saved + cb, addr + cb);
	VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &oldprotect);
	write_jmp(addr, hook_fn);
	VirtualProtect(addr, 5, oldprotect, &oldprotect);

	return (unsigned int)saved;
}