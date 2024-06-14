#ifndef CIPHER_H
#define CIPHER_H

#include "ThemidaSDK.h"
#include "GuardOptions.h"

#include <stdint.h>
#include <iostream>
#include <array>
#include <cstring>

#ifdef _MSC_VER
#define forceinline __forceinline
#elif defined(__GNUC__)
#define forceinline inline __attribute__((__always_inline__))
#elif defined(__CLANG__)
#if __has_attribute(__always_inline__)
#define forceinline inline __attribute__((__always_inline__))
#else
#define forceinline inline
#endif
#else
#define forceinline inline
#endif

#define WORDSIZE 0x100000000

const uint32_t A[8] = {
	0x4D34D34D, 0xD34D34D3,
	0x34D34D34, 0x4D34D34D,
	0xD34D34D3, 0x34D34D34,
	0x4D34D34D, 0xD34D34D3
};

inline uint32_t g(uint64_t u, uint64_t v)
{
	uint64_t hold = ((u + v) % WORDSIZE) * ((u + v) % WORDSIZE);
	uint32_t LSW = hold & 0xffffffff;
	uint32_t MSW = (hold >> 32) & 0xffffffff;
	uint32_t res = (LSW ^ MSW);

	return (LSW ^ MSW);
}

inline uint32_t rotl(uint32_t x, uint32_t l) {
	int res = (x << l);
	res |= (x >> (32 - l));
	return res;
}

using namespace std;

#pragma once
class RabbitCipher
{
	private:
		uint32_t MASTER_C[8];
		uint32_t MASTER_X[8];

		uint32_t X[8];
		uint32_t C[8];
		uint8_t b;
	public:
		void setup_key(uint8_t*);
		void load_iv(wchar_t*);
		void process(unsigned char*, int);

		void next_block(uint32_t* keystream)
		{
			MUTATE_START

			roll_next_state();

			uint16_t* ks_ptr = (uint16_t*)keystream;

			ks_ptr[0] = (X[0] & 0xffff) ^ ((X[5] >> 16) & 0xffff);
			ks_ptr[1] = ((X[0] >> 16) & 0xffff) ^ (X[3] & 0xffff);
			ks_ptr[2] = (X[2] & 0xffff) ^ ((X[7] >> 16) & 0xffff);
			ks_ptr[3] = ((X[2] >> 16) & 0xffff) ^ (X[5] & 0xffff);
			ks_ptr[4] = (X[4] & 0xffff) ^ ((X[1] >> 16) & 0xffff);
			ks_ptr[5] = ((X[4] >> 16) & 0xffff) ^ (X[7] & 0xffff);
			ks_ptr[6] = (X[6] & 0xffff) ^ ((X[3] >> 16) & 0xffff);
			ks_ptr[7] = ((X[6] >> 16) & 0xffff) ^ (X[1] & 0xffff);

			MUTATE_END
		}

		void roll_next_state()
		{
			MUTATE_START

			uint64_t temp;
			for (int j = 0; j < 8; j++)
			{
				temp = (uint64_t)C[j] + (uint64_t)A[j] + (uint64_t)b;
				b = temp > WORDSIZE;
				C[j] = (temp % WORDSIZE);
			}

			uint32_t G[8];
			for (int i = 0; i < 8; i++)
			{
				G[i] = g(X[i], C[i]);
			}

			X[0] = (G[0] + rotl(G[7], 16) + rotl(G[6], 16)) % WORDSIZE;
			X[1] = (G[1] + rotl(G[0], 8) + G[7]) % WORDSIZE;

			X[2] = (G[2] + rotl(G[1], 16) + rotl(G[0], 16)) % WORDSIZE;
			X[3] = (G[3] + rotl(G[2], 8) + G[1]) % WORDSIZE;

			X[4] = (G[4] + rotl(G[3], 16) + rotl(G[2], 16)) % WORDSIZE;
			X[5] = (G[5] + rotl(G[4], 8) + G[3]) % WORDSIZE;

			X[6] = (G[6] + rotl(G[5], 16) + rotl(G[4], 16)) % WORDSIZE;
			X[7] = (G[7] + rotl(G[6], 8) + G[5]) % WORDSIZE;

			MUTATE_END
		}
};


#endif
