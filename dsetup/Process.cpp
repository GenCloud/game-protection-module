#include "stdafx.h"
#include "GuardOptions.h"
#include "Process.h"
#include "ThemidaSDK.h"

ADDRESS_VALUE Process::SearchSignature(void* p_pvStartAddress, DWORD p_dwSize, void* p_pvBuffer, DWORD p_dwBufferSize)
{
	ADDRESS_VALUE dwMax = (ADDRESS_VALUE)p_pvStartAddress + p_dwSize;
	unsigned char c1 = 0, c2 = 0;
	bool bOk = false;

	for (DWORD i = 0; i < p_dwSize - p_dwBufferSize; i++)
	{
		bOk = false;

		for (DWORD j = 0; j < p_dwBufferSize; j++)
		{
			// c1 = from memory, c2 = from signature

			c1 = *(unsigned char*)((ADDRESS_VALUE)p_pvStartAddress + i + j);
			c2 = *(unsigned char*)((ADDRESS_VALUE)p_pvBuffer + j);

			// Check character

			if (c1 == c2 || c2 == '?')
			{
				bOk = true;
				continue;
			}
			else
			{
				bOk = false;
				break;
			}
		}

		// Check if we found the signature

		if (bOk) return (ADDRESS_VALUE)p_pvStartAddress + i;
	}

#if OPT_ENABLED(OPT_LOW_PT_EVENTS_LOG)
	printf("[ERROR] SearchSignature did not find the signature!\r\n");
#endif

	return 0;
}