#include "operations.h"

static uint8_t xtime_table[256][7] =
{
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 },
	{ 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B },
	{ 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x9B },
	{ 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 },
	{ 0x0A, 0x14, 0x28, 0x50, 0xA0, 0x5B, 0xB6 },
	{ 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x9B, 0x2D },
	{ 0x0E, 0x1C, 0x38, 0x70, 0xE0, 0xDB, 0xAD },
	{ 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C },
	{ 0x12, 0x24, 0x48, 0x90, 0x3B, 0x76, 0xEC },
	{ 0x14, 0x28, 0x50, 0xA0, 0x5B, 0xB6, 0x77 },
	{ 0x16, 0x2C, 0x58, 0xB0, 0x7B, 0xF6, 0xF7 },
	{ 0x18, 0x30, 0x60, 0xC0, 0x9B, 0x2D, 0x5A },
	{ 0x1A, 0x34, 0x68, 0xD0, 0xBB, 0x6D, 0xDA },
	{ 0x1C, 0x38, 0x70, 0xE0, 0xDB, 0xAD, 0x41 },
	{ 0x1E, 0x3C, 0x78, 0xF0, 0xFB, 0xED, 0xC1 },
	{ 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8 },
	{ 0x22, 0x44, 0x88, 0x0B, 0x16, 0x2C, 0x58 },
	{ 0x24, 0x48, 0x90, 0x3B, 0x76, 0xEC, 0xC3 },
	{ 0x26, 0x4C, 0x98, 0x2B, 0x56, 0xAC, 0x43 },
	{ 0x28, 0x50, 0xA0, 0x5B, 0xB6, 0x77, 0xEE },
	{ 0x2A, 0x54, 0xA8, 0x4B, 0x96, 0x37, 0x6E },
	{ 0x2C, 0x58, 0xB0, 0x7B, 0xF6, 0xF7, 0xF5 },
	{ 0x2E, 0x5C, 0xB8, 0x6B, 0xD6, 0xB7, 0x75 },
	{ 0x30, 0x60, 0xC0, 0x9B, 0x2D, 0x5A, 0xB4 },
	{ 0x32, 0x64, 0xC8, 0x8B, 0x0D, 0x1A, 0x34 },
	{ 0x34, 0x68, 0xD0, 0xBB, 0x6D, 0xDA, 0xAF },
	{ 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F },
	{ 0x38, 0x70, 0xE0, 0xDB, 0xAD, 0x41, 0x82 },
	{ 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02 },
	{ 0x3C, 0x78, 0xF0, 0xFB, 0xED, 0xC1, 0x99 },
	{ 0x3E, 0x7C, 0xF8, 0xEB, 0xCD, 0x81, 0x19 },
	{ 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB },
	{ 0x42, 0x84, 0x13, 0x26, 0x4C, 0x98, 0x2B },
	{ 0x44, 0x88, 0x0B, 0x16, 0x2C, 0x58, 0xB0 },
	{ 0x46, 0x8C, 0x03, 0x06, 0x0C, 0x18, 0x30 },
	{ 0x48, 0x90, 0x3B, 0x76, 0xEC, 0xC3, 0x9D },
	{ 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D },
	{ 0x4C, 0x98, 0x2B, 0x56, 0xAC, 0x43, 0x86 },
	{ 0x4E, 0x9C, 0x23, 0x46, 0x8C, 0x03, 0x06 },
	{ 0x50, 0xA0, 0x5B, 0xB6, 0x77, 0xEE, 0xC7 },
	{ 0x52, 0xA4, 0x53, 0xA6, 0x57, 0xAE, 0x47 },
	{ 0x54, 0xA8, 0x4B, 0x96, 0x37, 0x6E, 0xDC },
	{ 0x56, 0xAC, 0x43, 0x86, 0x17, 0x2E, 0x5C },
	{ 0x58, 0xB0, 0x7B, 0xF6, 0xF7, 0xF5, 0xF1 },
	{ 0x5A, 0xB4, 0x73, 0xE6, 0xD7, 0xB5, 0x71 },
	{ 0x5C, 0xB8, 0x6B, 0xD6, 0xB7, 0x75, 0xEA },
	{ 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A },
	{ 0x60, 0xC0, 0x9B, 0x2D, 0x5A, 0xB4, 0x73 },
	{ 0x62, 0xC4, 0x93, 0x3D, 0x7A, 0xF4, 0xF3 },
	{ 0x64, 0xC8, 0x8B, 0x0D, 0x1A, 0x34, 0x68 },
	{ 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8 },
	{ 0x68, 0xD0, 0xBB, 0x6D, 0xDA, 0xAF, 0x45 },
	{ 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5 },
	{ 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E },
	{ 0x6E, 0xDC, 0xA3, 0x5D, 0xBA, 0x6F, 0xDE },
	{ 0x70, 0xE0, 0xDB, 0xAD, 0x41, 0x82, 0x1F },
	{ 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F },
	{ 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04 },
	{ 0x76, 0xEC, 0xC3, 0x9D, 0x21, 0x42, 0x84 },
	{ 0x78, 0xF0, 0xFB, 0xED, 0xC1, 0x99, 0x29 },
	{ 0x7A, 0xF4, 0xF3, 0xFD, 0xE1, 0xD9, 0xA9 },
	{ 0x7C, 0xF8, 0xEB, 0xCD, 0x81, 0x19, 0x32 },
	{ 0x7E, 0xFC, 0xE3, 0xDD, 0xA1, 0x59, 0xB2 },
	{ 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D },
	{ 0x82, 0x1F, 0x3E, 0x7C, 0xF8, 0xEB, 0xCD },
	{ 0x84, 0x13, 0x26, 0x4C, 0x98, 0x2B, 0x56 },
	{ 0x86, 0x17, 0x2E, 0x5C, 0xB8, 0x6B, 0xD6 },
	{ 0x88, 0x0B, 0x16, 0x2C, 0x58, 0xB0, 0x7B },
	{ 0x8A, 0x0F, 0x1E, 0x3C, 0x78, 0xF0, 0xFB },
	{ 0x8C, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x60 },
	{ 0x8E, 0x07, 0x0E, 0x1C, 0x38, 0x70, 0xE0 },
	{ 0x90, 0x3B, 0x76, 0xEC, 0xC3, 0x9D, 0x21 },
	{ 0x92, 0x3F, 0x7E, 0xFC, 0xE3, 0xDD, 0xA1 },
	{ 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A },
	{ 0x96, 0x37, 0x6E, 0xDC, 0xA3, 0x5D, 0xBA },
	{ 0x98, 0x2B, 0x56, 0xAC, 0x43, 0x86, 0x17 },
	{ 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97 },
	{ 0x9C, 0x23, 0x46, 0x8C, 0x03, 0x06, 0x0C },
	{ 0x9E, 0x27, 0x4E, 0x9C, 0x23, 0x46, 0x8C },
	{ 0xA0, 0x5B, 0xB6, 0x77, 0xEE, 0xC7, 0x95 },
	{ 0xA2, 0x5F, 0xBE, 0x67, 0xCE, 0x87, 0x15 },
	{ 0xA4, 0x53, 0xA6, 0x57, 0xAE, 0x47, 0x8E },
	{ 0xA6, 0x57, 0xAE, 0x47, 0x8E, 0x07, 0x0E },
	{ 0xA8, 0x4B, 0x96, 0x37, 0x6E, 0xDC, 0xA3 },
	{ 0xAA, 0x4F, 0x9E, 0x27, 0x4E, 0x9C, 0x23 },
	{ 0xAC, 0x43, 0x86, 0x17, 0x2E, 0x5C, 0xB8 },
	{ 0xAE, 0x47, 0x8E, 0x07, 0x0E, 0x1C, 0x38 },
	{ 0xB0, 0x7B, 0xF6, 0xF7, 0xF5, 0xF1, 0xF9 },
	{ 0xB2, 0x7F, 0xFE, 0xE7, 0xD5, 0xB1, 0x79 },
	{ 0xB4, 0x73, 0xE6, 0xD7, 0xB5, 0x71, 0xE2 },
	{ 0xB6, 0x77, 0xEE, 0xC7, 0x95, 0x31, 0x62 },
	{ 0xB8, 0x6B, 0xD6, 0xB7, 0x75, 0xEA, 0xCF },
	{ 0xBA, 0x6F, 0xDE, 0xA7, 0x55, 0xAA, 0x4F },
	{ 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4 },
	{ 0xBE, 0x67, 0xCE, 0x87, 0x15, 0x2A, 0x54 },
	{ 0xC0, 0x9B, 0x2D, 0x5A, 0xB4, 0x73, 0xE6 },
	{ 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66 },
	{ 0xC4, 0x93, 0x3D, 0x7A, 0xF4, 0xF3, 0xFD },
	{ 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D },
	{ 0xC8, 0x8B, 0x0D, 0x1A, 0x34, 0x68, 0xD0 },
	{ 0xCA, 0x8F, 0x05, 0x0A, 0x14, 0x28, 0x50 },
	{ 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB },
	{ 0xCE, 0x87, 0x15, 0x2A, 0x54, 0xA8, 0x4B },
	{ 0xD0, 0xBB, 0x6D, 0xDA, 0xAF, 0x45, 0x8A },
	{ 0xD2, 0xBF, 0x65, 0xCA, 0x8F, 0x05, 0x0A },
	{ 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91 },
	{ 0xD6, 0xB7, 0x75, 0xEA, 0xCF, 0x85, 0x11 },
	{ 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC },
	{ 0xDA, 0xAF, 0x45, 0x8A, 0x0F, 0x1E, 0x3C },
	{ 0xDC, 0xA3, 0x5D, 0xBA, 0x6F, 0xDE, 0xA7 },
	{ 0xDE, 0xA7, 0x55, 0xAA, 0x4F, 0x9E, 0x27 },
	{ 0xE0, 0xDB, 0xAD, 0x41, 0x82, 0x1F, 0x3E },
	{ 0xE2, 0xDF, 0xA5, 0x51, 0xA2, 0x5F, 0xBE },
	{ 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25 },
	{ 0xE6, 0xD7, 0xB5, 0x71, 0xE2, 0xDF, 0xA5 },
	{ 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08 },
	{ 0xEA, 0xCF, 0x85, 0x11, 0x22, 0x44, 0x88 },
	{ 0xEC, 0xC3, 0x9D, 0x21, 0x42, 0x84, 0x13 },
	{ 0xEE, 0xC7, 0x95, 0x31, 0x62, 0xC4, 0x93 },
	{ 0xF0, 0xFB, 0xED, 0xC1, 0x99, 0x29, 0x52 },
	{ 0xF2, 0xFF, 0xE5, 0xD1, 0xB9, 0x69, 0xD2 },
	{ 0xF4, 0xF3, 0xFD, 0xE1, 0xD9, 0xA9, 0x49 },
	{ 0xF6, 0xF7, 0xF5, 0xF1, 0xF9, 0xE9, 0xC9 },
	{ 0xF8, 0xEB, 0xCD, 0x81, 0x19, 0x32, 0x64 },
	{ 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4 },
	{ 0xFC, 0xE3, 0xDD, 0xA1, 0x59, 0xB2, 0x7F },
	{ 0xFE, 0xE7, 0xD5, 0xB1, 0x79, 0xF2, 0xFF },
	{ 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A },
	{ 0x19, 0x32, 0x64, 0xC8, 0x8B, 0x0D, 0x1A },
	{ 0x1F, 0x3E, 0x7C, 0xF8, 0xEB, 0xCD, 0x81 },
	{ 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01 },
	{ 0x13, 0x26, 0x4C, 0x98, 0x2B, 0x56, 0xAC },
	{ 0x11, 0x22, 0x44, 0x88, 0x0B, 0x16, 0x2C },
	{ 0x17, 0x2E, 0x5C, 0xB8, 0x6B, 0xD6, 0xB7 },
	{ 0x15, 0x2A, 0x54, 0xA8, 0x4B, 0x96, 0x37 },
	{ 0x0B, 0x16, 0x2C, 0x58, 0xB0, 0x7B, 0xF6 },
	{ 0x09, 0x12, 0x24, 0x48, 0x90, 0x3B, 0x76 },
	{ 0x0F, 0x1E, 0x3C, 0x78, 0xF0, 0xFB, 0xED },
	{ 0x0D, 0x1A, 0x34, 0x68, 0xD0, 0xBB, 0x6D },
	{ 0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0 },
	{ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 },
	{ 0x07, 0x0E, 0x1C, 0x38, 0x70, 0xE0, 0xDB },
	{ 0x05, 0x0A, 0x14, 0x28, 0x50, 0xA0, 0x5B },
	{ 0x3B, 0x76, 0xEC, 0xC3, 0x9D, 0x21, 0x42 },
	{ 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2 },
	{ 0x3F, 0x7E, 0xFC, 0xE3, 0xDD, 0xA1, 0x59 },
	{ 0x3D, 0x7A, 0xF4, 0xF3, 0xFD, 0xE1, 0xD9 },
	{ 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74 },
	{ 0x31, 0x62, 0xC4, 0x93, 0x3D, 0x7A, 0xF4 },
	{ 0x37, 0x6E, 0xDC, 0xA3, 0x5D, 0xBA, 0x6F },
	{ 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF },
	{ 0x2B, 0x56, 0xAC, 0x43, 0x86, 0x17, 0x2E },
	{ 0x29, 0x52, 0xA4, 0x53, 0xA6, 0x57, 0xAE },
	{ 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35 },
	{ 0x2D, 0x5A, 0xB4, 0x73, 0xE6, 0xD7, 0xB5 },
	{ 0x23, 0x46, 0x8C, 0x03, 0x06, 0x0C, 0x18 },
	{ 0x21, 0x42, 0x84, 0x13, 0x26, 0x4C, 0x98 },
	{ 0x27, 0x4E, 0x9C, 0x23, 0x46, 0x8C, 0x03 },
	{ 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83 },
	{ 0x5B, 0xB6, 0x77, 0xEE, 0xC7, 0x95, 0x31 },
	{ 0x59, 0xB2, 0x7F, 0xFE, 0xE7, 0xD5, 0xB1 },
	{ 0x5F, 0xBE, 0x67, 0xCE, 0x87, 0x15, 0x2A },
	{ 0x5D, 0xBA, 0x6F, 0xDE, 0xA7, 0x55, 0xAA },
	{ 0x53, 0xA6, 0x57, 0xAE, 0x47, 0x8E, 0x07 },
	{ 0x51, 0xA2, 0x5F, 0xBE, 0x67, 0xCE, 0x87 },
	{ 0x57, 0xAE, 0x47, 0x8E, 0x07, 0x0E, 0x1C },
	{ 0x55, 0xAA, 0x4F, 0x9E, 0x27, 0x4E, 0x9C },
	{ 0x4B, 0x96, 0x37, 0x6E, 0xDC, 0xA3, 0x5D },
	{ 0x49, 0x92, 0x3F, 0x7E, 0xFC, 0xE3, 0xDD },
	{ 0x4F, 0x9E, 0x27, 0x4E, 0x9C, 0x23, 0x46 },
	{ 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6 },
	{ 0x43, 0x86, 0x17, 0x2E, 0x5C, 0xB8, 0x6B },
	{ 0x41, 0x82, 0x1F, 0x3E, 0x7C, 0xF8, 0xEB },
	{ 0x47, 0x8E, 0x07, 0x0E, 0x1C, 0x38, 0x70 },
	{ 0x45, 0x8A, 0x0F, 0x1E, 0x3C, 0x78, 0xF0 },
	{ 0x7B, 0xF6, 0xF7, 0xF5, 0xF1, 0xF9, 0xE9 },
	{ 0x79, 0xF2, 0xFF, 0xE5, 0xD1, 0xB9, 0x69 },
	{ 0x7F, 0xFE, 0xE7, 0xD5, 0xB1, 0x79, 0xF2 },
	{ 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72 },
	{ 0x73, 0xE6, 0xD7, 0xB5, 0x71, 0xE2, 0xDF },
	{ 0x71, 0xE2, 0xDF, 0xA5, 0x51, 0xA2, 0x5F },
	{ 0x77, 0xEE, 0xC7, 0x95, 0x31, 0x62, 0xC4 },
	{ 0x75, 0xEA, 0xCF, 0x85, 0x11, 0x22, 0x44 },
	{ 0x6B, 0xD6, 0xB7, 0x75, 0xEA, 0xCF, 0x85 },
	{ 0x69, 0xD2, 0xBF, 0x65, 0xCA, 0x8F, 0x05 },
	{ 0x6F, 0xDE, 0xA7, 0x55, 0xAA, 0x4F, 0x9E },
	{ 0x6D, 0xDA, 0xAF, 0x45, 0x8A, 0x0F, 0x1E },
	{ 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3 },
	{ 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33 },
	{ 0x67, 0xCE, 0x87, 0x15, 0x2A, 0x54, 0xA8 },
	{ 0x65, 0xCA, 0x8F, 0x05, 0x0A, 0x14, 0x28 },
	{ 0x9B, 0x2D, 0x5A, 0xB4, 0x73, 0xE6, 0xD7 },
	{ 0x99, 0x29, 0x52, 0xA4, 0x53, 0xA6, 0x57 },
	{ 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC },
	{ 0x9D, 0x21, 0x42, 0x84, 0x13, 0x26, 0x4C },
	{ 0x93, 0x3D, 0x7A, 0xF4, 0xF3, 0xFD, 0xE1 },
	{ 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61 },
	{ 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA },
	{ 0x95, 0x31, 0x62, 0xC4, 0x93, 0x3D, 0x7A },
	{ 0x8B, 0x0D, 0x1A, 0x34, 0x68, 0xD0, 0xBB },
	{ 0x89, 0x09, 0x12, 0x24, 0x48, 0x90, 0x3B },
	{ 0x8F, 0x05, 0x0A, 0x14, 0x28, 0x50, 0xA0 },
	{ 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20 },
	{ 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D },
	{ 0x81, 0x19, 0x32, 0x64, 0xC8, 0x8B, 0x0D },
	{ 0x87, 0x15, 0x2A, 0x54, 0xA8, 0x4B, 0x96 },
	{ 0x85, 0x11, 0x22, 0x44, 0x88, 0x0B, 0x16 },
	{ 0xBB, 0x6D, 0xDA, 0xAF, 0x45, 0x8A, 0x0F },
	{ 0xB9, 0x69, 0xD2, 0xBF, 0x65, 0xCA, 0x8F },
	{ 0xBF, 0x65, 0xCA, 0x8F, 0x05, 0x0A, 0x14 },
	{ 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94 },
	{ 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39 },
	{ 0xB1, 0x79, 0xF2, 0xFF, 0xE5, 0xD1, 0xB9 },
	{ 0xB7, 0x75, 0xEA, 0xCF, 0x85, 0x11, 0x22 },
	{ 0xB5, 0x71, 0xE2, 0xDF, 0xA5, 0x51, 0xA2 },
	{ 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63 },
	{ 0xA9, 0x49, 0x92, 0x3F, 0x7E, 0xFC, 0xE3 },
	{ 0xAF, 0x45, 0x8A, 0x0F, 0x1E, 0x3C, 0x78 },
	{ 0xAD, 0x41, 0x82, 0x1F, 0x3E, 0x7C, 0xF8 },
	{ 0xA3, 0x5D, 0xBA, 0x6F, 0xDE, 0xA7, 0x55 },
	{ 0xA1, 0x59, 0xB2, 0x7F, 0xFE, 0xE7, 0xD5 },
	{ 0xA7, 0x55, 0xAA, 0x4F, 0x9E, 0x27, 0x4E },
	{ 0xA5, 0x51, 0xA2, 0x5F, 0xBE, 0x67, 0xCE },
	{ 0xDB, 0xAD, 0x41, 0x82, 0x1F, 0x3E, 0x7C },
	{ 0xD9, 0xA9, 0x49, 0x92, 0x3F, 0x7E, 0xFC },
	{ 0xDF, 0xA5, 0x51, 0xA2, 0x5F, 0xBE, 0x67 },
	{ 0xDD, 0xA1, 0x59, 0xB2, 0x7F, 0xFE, 0xE7 },
	{ 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A },
	{ 0xD1, 0xB9, 0x69, 0xD2, 0xBF, 0x65, 0xCA },
	{ 0xD7, 0xB5, 0x71, 0xE2, 0xDF, 0xA5, 0x51 },
	{ 0xD5, 0xB1, 0x79, 0xF2, 0xFF, 0xE5, 0xD1 },
	{ 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10 },
	{ 0xC9, 0x89, 0x09, 0x12, 0x24, 0x48, 0x90 },
	{ 0xCF, 0x85, 0x11, 0x22, 0x44, 0x88, 0x0B },
	{ 0xCD, 0x81, 0x19, 0x32, 0x64, 0xC8, 0x8B },
	{ 0xC3, 0x9D, 0x21, 0x42, 0x84, 0x13, 0x26 },
	{ 0xC1, 0x99, 0x29, 0x52, 0xA4, 0x53, 0xA6 },
	{ 0xC7, 0x95, 0x31, 0x62, 0xC4, 0x93, 0x3D },
	{ 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD },
	{ 0xFB, 0xED, 0xC1, 0x99, 0x29, 0x52, 0xA4 },
	{ 0xF9, 0xE9, 0xC9, 0x89, 0x09, 0x12, 0x24 },
	{ 0xFF, 0xE5, 0xD1, 0xB9, 0x69, 0xD2, 0xBF },
	{ 0xFD, 0xE1, 0xD9, 0xA9, 0x49, 0x92, 0x3F },
	{ 0xF3, 0xFD, 0xE1, 0xD9, 0xA9, 0x49, 0x92 },
	{ 0xF1, 0xF9, 0xE9, 0xC9, 0x89, 0x09, 0x12 },
	{ 0xF7, 0xF5, 0xF1, 0xF9, 0xE9, 0xC9, 0x89 },
	{ 0xF5, 0xF1, 0xF9, 0xE9, 0xC9, 0x89, 0x09 },
	{ 0xEB, 0xCD, 0x81, 0x19, 0x32, 0x64, 0xC8 },
	{ 0xE9, 0xC9, 0x89, 0x09, 0x12, 0x24, 0x48 },
	{ 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3 },
	{ 0xED, 0xC1, 0x99, 0x29, 0x52, 0xA4, 0x53 },
	{ 0xE3, 0xDD, 0xA1, 0x59, 0xB2, 0x7F, 0xFE },
	{ 0xE1, 0xD9, 0xA9, 0x49, 0x92, 0x3F, 0x7E },
	{ 0xE7, 0xD5, 0xB1, 0x79, 0xF2, 0xFF, 0xE5 },
	{ 0xE5, 0xD1, 0xB9, 0x69, 0xD2, 0xBF, 0x65 }
};

static uint8_t gsb(uint8_t n)
{
	uint8_t i, bit;
	for(i = 0; i < 8; i++)
	{
		bit = 7 - i;
		if(n >> bit) return bit;
	}

	return 0;
}

uint8_t byte_mul(uint8_t a, uint8_t b)
{
	uint8_t bigbit = gsb(b);
	uint8_t acc;
	int i;

	acc = b & 1 ? a : 0;
	for(i = 1; i <= bigbit; i++)
	{
		if((b >> i) & 1) acc ^= xtime_table[a][i - 1];
	}

	return acc;
}

void col_mul(aes_word_t dest, aes_word_t other)
{
	int i, j;
	aes_word_t d = {0, 0, 0, 0};

	for(i = 0; i < Nb; i++)
	{
		for(j = 0; j < Nb; j++)
		{
			d[(i + j) % 4] ^= byte_mul(dest[i], other[j]);
		}
	}

	for(i = 0; i < Nb; i++)
		dest[i] = d[i];
}


static void shift_row_once(aes_block_t block, uint_fast8_t row)
{
	uint8_t prev = block[3][row];
	uint8_t current;
	int i;
	for(i = 0; i < 4; i++)
	{
		current = block[i][row];
		block[i][row] = prev;
		prev = current;
	}
}

void shift_row(aes_block_t block, uint_fast8_t row, int amt)
{
	int i;

	row %= 4;

	while(amt < 4) amt += 4;
	amt %= 4;

	for(i = 0; i < amt; i++)
		shift_row_once(block, row);
}

