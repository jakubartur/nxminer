#ifndef __UINT256_H__
#define __UINT256_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// arith_uint256(0)
static const uint8_t UINT256_ZERO[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
// arith_uint256(0x1d00ffff);
static const uint8_t UINT256_DIFF1[32] = {00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,0xff,0xff,00,00,00,00};
// arith_uint256(1000);
static const uint8_t UINT256_1000[32] =  {232,03,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
// arith_uint256(10000)
static const uint8_t UINT256_10000[32] =  {0x10,0x27,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
// arith uint256(1000000)
static const uint8_t UINT256_1000000[32] =  {0x40,0x42,0x0f,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
// arith uint256(100000000)
static const uint8_t UINT256_100000000[32] =  {0x00,0xe1,0xf5,0x05,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

void uint128_to_string(const uint8_t* a, char** str);
void uint128_print_string(const uint8_t* a);

void uint256_to_string(const uint8_t* a, char** str);
void uint256_print_string(const uint8_t* a);
void uint64_to_uint256(uint64_t value, uint8_t* res);
void uint256_assign_left_shift(uint8_t* pn, uint32_t shift);
void uint256_assign_right_shift(uint8_t* pn, uint32_t shift);
void uint256_assign_subtract(uint8_t* a, const uint8_t* b);
void uint128_assign_add(uint8_t* a, const uint64_t b);
void uint256_assign_add(uint8_t* a, const uint64_t b);
bool uint256_divide(const uint8_t* a, const uint8_t* b, uint8_t* res);
void uint256_multiply(const uint8_t* a, const uint8_t* b, uint8_t* res);
void uint256_set_compact(uint8_t* res, const uint32_t* nCompact, bool* pfNegative, bool* pfOverflow);

#endif
