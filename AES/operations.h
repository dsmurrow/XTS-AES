#ifndef OPERATIONS_H
#define OPERATIONS_H

#include "aes.h"

uint8_t byte_mul(uint8_t, uint8_t);
void shift_row(aes_block_t, uint_fast8_t, int);
void col_mul(aes_word_t, aes_word_t);

#endif

