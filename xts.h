#ifndef XTS_H
#define XTS_H

#include <inttypes.h>
#include <stddef.h>

void xts_aes_enc(uint8_t*, size_t, const uint8_t*, uint64_t);
void xts_aes_dec(uint8_t*, size_t, const uint8_t*, uint64_t);

#endif

