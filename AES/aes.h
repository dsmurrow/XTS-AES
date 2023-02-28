#ifndef AES_H
#define AES_H

#include <inttypes.h>
#include <stddef.h>

#define Nb 4
#define Nk 8
#define Nr 14

typedef uint8_t aes_word_t[4];
typedef aes_word_t aes_block_t[Nb];
typedef aes_word_t aes_key_t[Nk];
typedef aes_word_t aes_key_schedule[Nb * (Nr + 1)];

void aes_fill_key(const uint8_t[Nb * Nk], aes_key_t);
void aes_fill_block(const uint8_t*, size_t, aes_block_t);
size_t aes_fill_blocks(const uint8_t*, size_t, aes_block_t**);
void aes_empty_block(aes_block_t, uint8_t*, size_t);
void aes_gen_key_schedule(const aes_key_t, aes_key_schedule);

void aes_enc_block(aes_block_t, aes_key_schedule);
void aes_dec_block(aes_block_t, aes_key_schedule);

#endif

