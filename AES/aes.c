#include "transformations.h"

#include <stdlib.h>

void aes_fill_key(const uint8_t bytes[Nb * Nk], aes_key_t key)
{
	int i, j;
	for(i = 0; i < Nk; i++)
	{
		for(j = 0; j < 4; j++)
		{
			key[i][j] = bytes[(i * 4) + j];
		}
	}
}

size_t aes_fill_blocks(const uint8_t *bytes, size_t len, aes_block_t **blocks)
{
	int i, j;
	size_t b, c;
	size_t n_blocks = (len / sizeof(aes_block_t)) + (len % sizeof(aes_block_t) != 0);

	*blocks = calloc(len, sizeof(aes_block_t));

	for(b = 0, c = 0; b < n_blocks && c < len; b++)
		for(i = 0; i < Nb && c < len; i++)
			for(j = 0; j < 4 && c < len; j++)
				(*blocks)[b][i][j] = bytes[c++];

	return n_blocks;
}

void aes_gen_key_schedule(const aes_key_t key, aes_key_schedule w)
{
	KeyExpansion(key, w);
}

void aes_enc_block(aes_block_t block, aes_key_schedule w)
{
	int r;

	AddRoundKey(block, w, 0);

	for(r = 1; r < Nr; r++)
	{
		SubBytes(block);
		ShiftRows(block);
		MixColumns(block);
		AddRoundKey(block, w, r);
	}

	SubBytes(block);
	ShiftRows(block);
	AddRoundKey(block, w, Nr);
}

void aes_dec_block(aes_block_t block, aes_key_schedule w)
{
	int r;

	AddRoundKey(block, w, Nr);

	for(r = Nr - 1; r >= 1; r--)
	{
		InvShiftRows(block);
		InvSubBytes(block);
		AddRoundKey(block, w, r);
		InvMixColumns(block);
	}

	InvShiftRows(block);
	InvSubBytes(block);
	AddRoundKey(block, w, 0);
}

