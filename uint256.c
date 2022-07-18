#include "uint256.h"

void uint128_to_string(const uint8_t* a, char** str)
{
    // assert str is null to not leak memory on malloc
    //assert(str == NULL);
    *str = malloc(32 + 1);
    unsigned int i;
    for (i = 0; i < 16; ++i)
    {
        sprintf(*str + (i * 2), "%02x", a[i]);
    }
}

void uint128_print_string(const uint8_t* a)
{
    char* str_a = NULL;
    uint128_to_string(a, &str_a);
    printf("%s", str_a);
    free(str_a);
}

void uint256_to_string(const uint8_t* a, char** str)
{
    // assert str is null to not leak memory on malloc
    //assert(str == NULL);
    *str = malloc(64 + 1);
    unsigned int i;
    for (i = 0; i < 32; ++i)
    {
        sprintf(*str + (i * 2), "%02x", a[i]);
    }
}


void uint256_print_string(const uint8_t* a)
{
    char* str_a = NULL;
    uint256_to_string(a, &str_a);
    printf("%s", str_a);
    free(str_a);
}

void uint64_to_uint256(uint64_t value, uint8_t* res)
{
    uint32_t* res32 = (uint32_t*)res;
    res32[0] = (uint32_t)value;
    res32[1] = (uint32_t)(value >> 32);
    for (int i = 2; i < 8; i++)
    {
        res32[i] = 0;
    }
}

void uint32_to_uint256(uint32_t value, uint8_t* res)
{
    uint32_t* res32 = (uint32_t*)res;
    res32[0] = value;
    for (int i = 1; i < 8; i++)
    {
        res32[i] = 0;
    }
}

uint32_t uint256_get_bits(uint8_t* a)
{
    uint32_t* a32 = (uint32_t*)a;
    for (int32_t pos = 7; pos >= 0; pos--)
    {
        if (a32[pos])
        {
            for (int32_t bits = 31; bits > 0; bits--)
            {
                if (a32[pos] & 1U << bits)
                    return 32 * pos + bits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}

// operator <<=, modifies a
void uint256_assign_left_shift(uint8_t* pn, uint32_t shift)
{
    // copy pn to a
    uint8_t a[32];
    memcpy(a, pn, 32);
    // clear pn
    memcpy(pn, UINT256_ZERO, 32);
    uint32_t* pn32 = (uint32_t*)pn;
    uint32_t* a32 = (uint32_t*)a;
    int32_t k = shift / 32;
    shift = shift % 32;
    for (int32_t i = 0; i < 8; ++i)
    {
        if (i + k + 1 < 8 && shift != 0)
        {
            pn32[i + k + 1] |= (a32[i] >> (32 - shift));
        }
        if (i + k < 8)
        {
            pn32[i + k] |= (a32[i] << shift);
        }
    }
}

// operator >>=, modifies a
void uint256_assign_right_shift(uint8_t* pn, uint32_t shift)
{
    // copy pn to a
    uint8_t a[32];
    memcpy(a, pn, 32);
    // clear pn
    memcpy(pn, UINT256_ZERO, 32);
    uint32_t* pn32 = (uint32_t*)pn;
    uint32_t* a32 = (uint32_t*)a;
    int32_t k = shift / 32;
    shift = shift % 32;
    for (int32_t i = 0; i < 8; ++i)
    {
        if (i - k - 1 >= 0 && shift != 0)
        {
            pn32[i - k - 1] |= (a32[i] << (32 - shift));
        }
        if (i - k >= 0)
        {
            pn32[i - k] |= (a32[i] >> shift);
        }
    }
}

// operator -=, modifies a
void uint256_assign_subtract(uint8_t* a, const uint8_t* b)
{
    // make b negative
    uint8_t bneg[32];
    memcpy(bneg, UINT256_ZERO, 32);
    uint32_t* b32 = (uint32_t*)b;
    uint32_t* bneg32 = (uint32_t*)bneg;
    int32_t i = 0;
    for (i = 0; i < 8; i++)
    {
        bneg32[i] = ~b32[i];
    }
    i = 0;
    while (++bneg32[i] == 0 && i < 8 - 1)
    {
        i++;
    }
    // add the negative
    uint64_t carry = 0;
    uint32_t* a32 = (uint32_t*)a;
    for (i = 0; i < 8; i++)
    {
        uint64_t n = carry + (uint64_t)a32[i] + (uint64_t)bneg32[i];
        a32[i] = (n & 0x00000000ffffffff);
        carry = n >> 32;
    }
}

static int32_t uint256_compare_to(const uint8_t* a, const uint8_t* b)
{
    uint32_t* a32 = (uint32_t*)a;
    uint32_t* b32 = (uint32_t*)b;
    for (int32_t i = 8 - 1; i >= 0; i--)
    {
        if (a32[i] < b32[i])
            return -1;
        if (a32[i] > b32[i])
            return 1;
    }
    return 0;
}

bool uint256_divide(const uint8_t* a, const uint8_t* b, uint8_t* res)
{
    uint8_t div[32];
    memcpy(div, b, 32);
    uint8_t num[32];
    memcpy(num, a, 32);
    memcpy(res, UINT256_ZERO, 32);
    int32_t num_bits = uint256_get_bits(num);
    int32_t div_bits = uint256_get_bits(div);
    if (div_bits == 0)
    {
        return false;
    }
    if (div_bits > num_bits)
    {
        // result is 0
        return true;
    }
    int32_t shift = num_bits - div_bits;
    uint256_assign_left_shift(div, shift); // shift so that div and num align.
    uint32_t* res32 = (uint32_t*)res;
    while (shift >= 0)
    {
        if (uint256_compare_to(num, div) >= 0)
        {
            uint256_assign_subtract(num, div);
            res32[shift / 32] |= (1 << (shift & 31)); // set a bit of the result.
        }
        uint256_assign_right_shift(div, 1); // shift back.
        shift--;
    }
    return true;
}

void uint256_multiply(const uint8_t* a, const uint8_t* b, uint8_t* res)
{
    memcpy(res, UINT256_ZERO, 32);
    uint32_t* a32 = (uint32_t*)a;
    uint32_t* b32 = (uint32_t*)b;
    uint32_t* res32 = (uint32_t*)res;
    for (int32_t j = 0; j < 8; j++)
    {
        uint64_t carry = 0;
        for (int32_t i = 0; i + j < 8; i++)
        {
            uint64_t n = carry + res32[i + j] + (uint64_t)a32[j] * b32[i];
            res32[i + j] = n & 0x00000000ffffffff;
            carry = n >> 32;
        }
    }
}

void uint256_set_compact(uint8_t* _res, const uint32_t* nCompact, bool* pfNegative, bool* pfOverflow)
{
    uint32_t* res = (uint32_t*)_res;
    const int32_t width = 8; // 256 / 32
    const int32_t nSize = (*nCompact) >> 24;
    uint32_t nWord = (*nCompact) & 0x007fffff;
    if (nSize <= 3)
    {
        nWord >>= 8 * (3 - nSize);
        res[0] = nWord;
    }
    else
    {
        res[0] = nWord;
        uint32_t res_copy[8];
        memcpy(res_copy, res, 8);
        memset(res, 0, 8);
        uint32_t nShift = 8 * (nSize - 3);
        for (int i = 0; i < width; i++)
        {
            res[i] = 0;
        }
        int32_t k = nShift / 32;
        nShift = nShift % 32;
        for (int32_t i = 0; i < width; i++)
        {
            if (i + k + 1 < width && nShift != 0)
            {
                res[i + k + 1] |= (res_copy[i] >> (32 - nShift));
            }
            if (i + k < width)
            {
                res[i + k] |= (res_copy[i] << nShift);
            }
        }
    }
    if (pfNegative)
    {
        *pfNegative = nWord != 0 && ((*nCompact) & 0x00800000) != 0;
    }
    if (pfOverflow)
    {
        *pfOverflow = nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32));
    }
}
