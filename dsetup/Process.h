#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h> 
#include "Utils.h"

using namespace std;

// Address type

#if defined _M_X64
#define ADDRESS_VALUE uint64_t
#elif defined _M_IX86
#define ADDRESS_VALUE uint32_t
#endif

// Process and PE stuff

class Process
{
public:
	static ADDRESS_VALUE SearchSignature(void* p_pvStartAddress, DWORD p_dwSize, void* p_pvBuffer, DWORD p_dwBufferSize);
};

#endif