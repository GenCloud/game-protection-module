#include "stdafx.h"
#include "RabbitCipher.h"

void RabbitCipher::setup_key(uint8_t* key)
{
	VM_START_WITHLEVEL(20)

	std::fill(std::begin(X), std::end(X), (uint32_t) 0x00);
	std::fill(std::begin(C), std::end(C), (uint32_t) 0x00);
	std::fill(std::begin(MASTER_X), std::end(MASTER_X), (uint32_t)0x00);
	std::fill(std::begin(MASTER_C), std::end(MASTER_C), (uint32_t)0x00);

	uint8_t keyInit[8];
	memcpy(keyInit, key, 8);

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
	printf("Setup key = ");

	for (int i = 0; i < sizeof(keyInit); i++)
		printf("%02x ", keyInit[i]);
	printf("\r\n");
#endif

	for (int j = 0; j < 8; j++)
	{
		if (j % 2)
		{
			X[j] = (uint32_t)((uint32_t)keyInit[(j + 5) & 0x7] << 16 | (uint32_t)keyInit[(j + 4) & 0x7]);
			C[j] = (uint32_t)((uint32_t)keyInit[j] << 16 | (uint32_t)keyInit[(j + 1) & 0x7]);
		}
		else
		{
			X[j] = (uint32_t)((uint32_t)keyInit[(j + 1) & 0x7] << 16 | (uint32_t)keyInit[j]);
			C[j] = (uint32_t)((uint32_t)keyInit[(j + 4) & 0x7] << 16 | (uint32_t)keyInit[(j + 5) & 0x7]);
		}
	}

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
	printf("X = ");

	for (int i = 0; i < 8; i++)
		printf("%d ", X[i]);
	printf("\r\n");

	printf("C = ");

	for (int i = 0; i < 8; i++)
		printf("%d ", C[i]);
	printf("\r\n");
#endif

	for (int i = 0; i < 4; i++)
	{
		roll_next_state();
	}

	for (int j = 0; j < 8; j++)
	{
		C[j] = C[j] ^ X[(j + 4) & 0x7];
	}

	for (int j = 0; j < 8; j++)
	{
		MASTER_C[j] = C[j];
		MASTER_X[j] = X[j];
	}

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
	printf("next C = ");

	for (int i = 0; i < 8; i++)
		printf("%d ", C[i]);
	printf("\r\n");
#endif

	VM_END
}

void RabbitCipher::load_iv(wchar_t* staticKey)
{
	VM_START_WITHLEVEL(21)

	uint8_t iv[8];
	for (int i = 0; i < 8; i++) 
	{
		iv[i] = (uint8_t) (staticKey[i] & 0xFF);
	}

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
	printf("Load IV = ");

	for (int i = 0; i < 8; i++)
		printf("%02x ", iv[i]);
	printf("\r\n");
#endif

	X[0] = MASTER_X[0];
	X[1] = MASTER_X[1];
	X[2] = MASTER_X[2];
	X[3] = MASTER_X[3];
	X[4] = MASTER_X[4];
	X[5] = MASTER_X[5];
	X[6] = MASTER_X[6];
	X[7] = MASTER_X[7];

	C[0] = MASTER_C[0] ^ iv[0];
	C[1] = MASTER_C[1] ^ ((iv[3] << 16) | iv[1]);
	C[2] = MASTER_C[2] ^ iv[1];
	C[3] = MASTER_C[3] ^ ((iv[2] << 16) | iv[0]);
	C[4] = MASTER_C[4] ^ iv[0];
	C[5] = MASTER_C[5] ^ ((iv[3] << 16) | iv[1]);
	C[6] = MASTER_C[6] ^ iv[1];
	C[7] = MASTER_C[7] ^ ((iv[2] << 16) | iv[0]);

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
	printf("IV X = ");

	for (int i = 0; i < 8; i++)
		printf("%d ", X[i]);
	printf("\r\n");

	printf("IV C = ");

	for (int i = 0; i < 8; i++)
		printf("%d ", C[i]);
	printf("\r\n");
#endif

	for (int i = 0; i < 4; i++)
	{
		roll_next_state();
	}

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
	printf("IV next C = ");

	for (int i = 0; i < 8; i++)
		printf("%d ", C[i]);
	printf("\r\n");
#endif

	VM_END
}

void RabbitCipher::process(unsigned char* raw, int size)
{
#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
	printf("Process bytes\r\n");
#endif

	uint64_t size_left = size;
	uint32_t keystream[4];

	uint32_t j = 0;

	while (size_left > 15)
	{
		next_block(keystream);

		raw[j] = raw[j] ^ keystream[0];

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
		printf("S0 processed byte - %d\r\n", raw[j]);
#endif

		j++;

		raw[j] = raw[j] ^ keystream[1];

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
		printf("S1 processed byte - %d\r\n", raw[j]);
#endif

		j++;

		raw[j] = raw[j] ^ keystream[2];

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
		printf("S2 processed byte - %d\r\n", raw[j]);
#endif

		j++;

		raw[j] = raw[j] ^ keystream[3];

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
		printf("S3 processed byte - %d\r\n", raw[j]);
#endif

		j++;

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
		printf("Size - %d, left - %d\r\n", size, size_left);
		printf("S0 - %d S1 - %d S2 - %d S3 - %d\r\n", keystream[0], keystream[1], keystream[2], keystream[3]);
#endif

		size_left -= 16;
	}

	if (size_left > 0)
	{

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
		printf("Size left - %d\r\n", size_left);
#endif

		next_block(keystream);

		while (size_left > 0)
		{
			for (int i = 0; i < 4; i++) {
				if (size_left > 0) {
					uint32_t key = keystream[i];

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
					printf("key - %d\r\n", key);
#endif

					raw[j] = raw[j] ^ key;

#if OPT_ENABLED(OPT_CIPHER_EVENTS_LOG)
					printf("left processed byte - %d\r\n", raw[j]);
#endif

					j++;
					size_left--;
				}
			}
		}
	}
}

