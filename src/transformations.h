#ifndef TRANSFORMATIONS_H
#define TRANSFORMATIONS_H

#include "aes.h"

void KeyExpansion(const aes_key_t, aes_key_schedule);

void SubBytes(aes_block_t);
void InvSubBytes(aes_block_t);

void ShiftRows(aes_block_t);
void InvShiftRows(aes_block_t);

void MixColumns(aes_block_t);
void InvMixColumns(aes_block_t);

void AddRoundKey(aes_block_t, aes_key_schedule, int);

#endif

