#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "utils.h"
// Inverse Rijndael SBOX 
uint8_t inv_sbox[BLOCK_SIZE * BLOCK_SIZE] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Pseudo constant time lookup function
uint8_t get_inv_sbox_value(uint8_t val) 
{
    size_t i;
    int b;
    uint8_t ret = inv_sbox[0];
    for (i = 1; i < (BLOCK_SIZE * BLOCK_SIZE); i++) {
        b = check_equality(i, (size_t)val);
        copy_byte(&ret, &inv_sbox[i], b);
    }
    return ret;
}

void inv_sub_bytes(uint8_t (*in)[WORD_SIZE]) 
{
    assert(valid_pointer(in) != 0);
    for (int i = 0; i < WORD_SIZE; i++) {
        for (int j = 0; j < WORD_SIZE; j++) {
            in[i][j] = get_inv_sbox_value(in[i][j]);
        }
    }
}

void inv_shift_rows(uint8_t (*in)[WORD_SIZE]) 
{
    assert(valid_pointer(in) != 0);
    uint8_t temp = {0x00};
    temp = in[1][0];
    in[1][0] = in[1][3];
    in[1][3] = in[1][2];
    in[1][2] = in[1][1];
    in[1][1] = temp;

    //Swap 2,0  and 2,2
    temp = in[2][0];
    in[2][0] = in[2][2];
    in[2][2] = temp;
    
    //swap 2,1 and 2,3
    temp = in[2][1];
    in[2][1] = in[2][3];
    in[2][3] = temp;

    temp = in[3][0];
    in[3][0]= in[3][1];
    in[3][1]= in[3][2];
    in[3][2]= in[3][3];
    in[3][3]= temp;
}

uint8_t multiply_by_09(uint8_t val)
{
    //x×9=(((x×2)×2)×2)+x
    return (xtime(xtime(xtime(val))) ^ val);
}

uint8_t multiply_by_0b(uint8_t val)
{
    //x×11=((((x×2)×2)+x)×2)+x
    return (xtime(xtime(xtime(val)) ^ val) ^ val);
}

uint8_t multiply_by_0d(uint8_t val)
{
    //x×13=((((x×2)+x)×2)×2)+x
    return (xtime(xtime(xtime(val) ^ val)) ^ val);
}

uint8_t multiply_by_0e(uint8_t val)
{
    //x×14=((((x×2)+x)×2)+x)×2
    return xtime((xtime(xtime(val) ^ val) ^ val));
}

void inv_mix_columns(uint8_t (*in)[WORD_SIZE])
{
    assert(valid_pointer(in) != 0);
    uint8_t old_col[WORD_SIZE] = {0x00};
    for (int i = 0; i < WORD_SIZE; i++) {
        old_col[0] = in[0][i];
        old_col[1] = in[1][i];
        old_col[2] = in[2][i];
        old_col[3] = in[3][i];
        // this going to be implemented as a series of multiply by two followed by an xor with rest of the values;
        // newC1 = (0x0e * c1) ^ (0x0b * c2) ^ (0x0d * c3) ^ (0x09 * c4);
        in[0][i] = multiply_by_0e(old_col[0]) ^ multiply_by_0b(old_col[1]) ^ multiply_by_0d(old_col[2]) ^ multiply_by_09(old_col[3]);
        // newC2 = (0x09 * c1) ^ (0x0e * c2) ^ (0x0b * c3) ^ (0x0d * c4);
        in[1][i] = multiply_by_09(old_col[0]) ^ multiply_by_0e(old_col[1]) ^ multiply_by_0b(old_col[2]) ^ multiply_by_0d(old_col[3]);
        // newC3 = (0x0d * c1) ^ (0x09 * c2) ^ (0x0e * c3) ^ (0x0b * c4);
        in[2][i] = multiply_by_0d(old_col[0]) ^ multiply_by_09(old_col[1]) ^ multiply_by_0e(old_col[2]) ^ multiply_by_0b(old_col[3]);
        // newC4 = (0x0b * c1) ^ (0x0d * c2) ^ (0x09 * c3) ^ (0x0e * c4);
        in[3][i] = multiply_by_0b(old_col[0]) ^ multiply_by_0d(old_col[1]) ^ multiply_by_09(old_col[2]) ^ multiply_by_0e(old_col[3]);
    }
}

void inv_cipher(uint8_t* in, uint8_t* out, uint8_t* expanded_key, int Nk)
{
    assert(valid_pointer(in) != 0);
    assert(valid_pointer(out) != 0);
    assert(valid_pointer(expanded_key) != 0);
    //Initialize with double braces to ensure that all objects are 0'd
    uint8_t state[WORD_SIZE][WORD_SIZE] = {{0x00}};
    uint8_t temp[BLOCK_SIZE] = {0x00}; 
    convert_to_matrix(in, state);
    int Nr = getNr(Nk);
    memcpy(temp, expanded_key + (Nr * WORD_SIZE * WORD_SIZE), BLOCK_SIZE);
    uint8_t roundKey[WORD_SIZE][WORD_SIZE] = {{0x00}};
    convert_to_matrix(temp, roundKey);
    
    add_round_key(state, roundKey);

    int round;
    int n = 1;
    for (round = Nr - 1; round >= 1; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        memcpy(temp, expanded_key + (round * WORD_SIZE * WORD_SIZE), BLOCK_SIZE);
        convert_to_matrix(temp, roundKey);
        add_round_key(state, roundKey);
        inv_mix_columns(state); 
        n ++;
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    memcpy(temp, expanded_key, BLOCK_SIZE);
    convert_to_matrix(temp, roundKey);
    add_round_key(state, roundKey);
    convert_to_array(state, out);
}
