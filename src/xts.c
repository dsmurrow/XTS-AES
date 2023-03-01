#include "xts.h"

#include "aes.h"

static inline void copy_block(aes_block_t dest, const aes_block_t src)
{
	int i, j;
	for(i = 0; i < Nb; i++)
		for(j = 0; j < 4; j++)
			dest[i][j] = src[i][j];
}

static inline void xor_block(aes_block_t dest, const aes_block_t other)
{
	int i, j;
	for(i = 0; i < Nb; i++)
		for(j = 0; j < 4; j++)
			dest[i][j] ^= other[i][j];
}

static void mul_a(aes_block_t block)
{
	/*int x, y;
	uint8_t cin, cout;
	for(x = 0; x < 4; x++)
	{
		for(y = 0, cin = 0; y < 4; y++)
		{
			cout = block[x][y] >> 7;
			block[x][y] <<= 1;
			block[x][y] |= cin;
			cin = cout;
		}
	}

	if(cout) block[0][0] ^= 0x87;*/

	uint8_t i = 16;
	uint8_t carry = block[3][3] & 0x80;
	while(--i)
	{
		uint8_t prev = block[(i - 1) / 4][(i - 1) % 4];
		uint8_t val = block[i / 4][i % 4];
		block[i / 4][i % 4] = (val << 1) | (prev & 0x80 ? 1 : 0);
	}
	block[0][0] = (block[0][0] << 1) ^ (carry ? 0x87 : 0);
}

static void mul_a_exp(aes_block_t block, uint64_t i)
{
	uint64_t iter;
	for(iter = 0; iter < i; iter++)
		mul_a(block);
}

static void xts_enc_block(aes_block_t block, aes_key_schedule w, aes_block_t tweak)
{
	xor_block(block, tweak);

	aes_enc_block(block, w);

	xor_block(block, tweak);
}

static void xts_dec_block(aes_block_t block, aes_key_schedule w, aes_block_t tweak)
{
	xor_block(block, tweak);

	aes_dec_block(block, w);

	xor_block(block, tweak);
}

void xts_aes_enc(uint8_t *P, size_t pl, const uint8_t *K, uint64_t i)
{
	uint8_t b = pl % 16;
	uint64_t q;
	size_t m, n_blocks;
	aes_block_t tweak, *blocks;
	aes_key_t K1, K2;
	aes_key_schedule wK1, wK2; 

	/* K = K1 | K2 */
	for(q = 0; q < 4 * Nk; q++)
	{
		K1[q / 4][q % 4] = K[q];
		K2[q / 4][q % 4] = K[(4 * Nk) + q];
	}

	aes_fill_block((uint8_t*) &i, 8, tweak);

	n_blocks = aes_fill_blocks(P, pl, &blocks);
	m = !b ? n_blocks : n_blocks - 1;

	aes_gen_key_schedule(K1, wK1);
	aes_gen_key_schedule(K2, wK2);

	aes_enc_block(tweak, wK2);

	for(q = 0; m >= 2 && q <= m - 2; q++)
	{
		xts_enc_block(blocks[q], wK1, tweak);
		mul_a(tweak);
	}

	if(b == 0)
	{
		xts_enc_block(blocks[m - 1], wK1, tweak);
	}
	else
	{
		int x, y, c;
		aes_block_t CC, PP;

		copy_block(CC, blocks[m - 1]);
		xts_enc_block(CC, wK1, tweak);
		mul_a(tweak);

		copy_block(PP, blocks[m]);
		for(c = 16 - b; c < 16 ; c++) /* I think this initializes it right */
		{
			PP[c / 4][c % 4] = CC[c / 4][c % 4];
		}

		for(x = 0; x < 4 && c < b; x++)
			for(y = 0; y < 4 && c < b; y++, b++)
				blocks[m][x][y] = CC[x][y];

		copy_block(blocks[m - 1], PP);
		xts_enc_block(blocks[m - 1], wK1, tweak);
	}

	for(m = 0; m < n_blocks - 1; m++)
	{
		aes_empty_block(blocks[m], &P[16 * m], 16);
	}
	aes_empty_block(blocks[m], &P[16 * m], b == 0 ? 16 : b);

}

void xts_aes_dec(uint8_t *P, size_t pl, const uint8_t *K, uint64_t i)
{
	uint8_t b = pl % 16;
	uint64_t q;
	size_t m, n_blocks;
	aes_block_t tweak, *blocks;
	aes_key_t K1, K2;
	aes_key_schedule wK1, wK2;

	for(q = 0; q < 4 * Nk; q++)
	{
		K1[q / 4][q % 4] = K[q];
		K2[q / 4][q % 4] = K[(4 * Nk) + q];
	}

	aes_fill_block((uint8_t*) &i, 8, tweak);

	n_blocks = aes_fill_blocks(P, pl, &blocks);
	m = !b ? n_blocks : n_blocks - 1;

	aes_gen_key_schedule(K1, wK1);
	aes_gen_key_schedule(K2, wK2);

	aes_enc_block(tweak, wK2);

	for(q = 0; m >= 2 && q <= m - 2; q++)
	{
		xts_dec_block(blocks[q], wK1, tweak);
		mul_a(tweak);
	}

	if(b == 0)
	{
		xts_dec_block(blocks[m - 1], wK1, tweak);
	}
	else
	{
		int x, y, c;
		aes_block_t CC, PP, tweak_m;

		copy_block(tweak_m, tweak);
		mul_a(tweak_m);

		copy_block(PP, blocks[m - 1]);
		xts_dec_block(PP, wK1, tweak_m);

		copy_block(CC, blocks[m]);
		for(c = 16 - b; c < 16; c++)
		{
			CC[c / 4][c % 4] = PP[c / 4][c % 4];
		}

		for(x = 0; x < Nb; x++)
			for(y = 0; y < 4; y++)
				blocks[m][x][y] = PP[x][y];

		xts_dec_block(CC, wK1, tweak);
	}

	for(m = 0; m < n_blocks - 1; m++)
		aes_empty_block(blocks[m], &P[16 * m], 16);
	aes_empty_block(blocks[m], &P[16 * m], b == 0 ? 16 : b);
}

