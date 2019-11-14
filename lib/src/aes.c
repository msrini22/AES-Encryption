#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include "aes.h"
#include "utils.h"
#define Nb 4

// The Rjndael substituition box
uint8_t sbox[BLOCK_SIZE * BLOCK_SIZE] =  {
 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
 0x51 ,0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// secures a memory area and generates a random key, and writes the key into `key`
// complies with MEM06-C to ensure key is not written to disk
void generate_secure_random_key(uint8_t** key, uint8_t** secret_buf, size_t keysize)
{
    struct rlimit limit;
    limit.rlim_cur = 0;
    limit.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &limit) != 0) {
        printf("ERROR: Unable to set core size to 0. Exiting\n");
        exit(-1);
    }

    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize == -1) {
        printf("ERROR: Page size is reported as -1. Exiting\n");
        exit(-1);
    }
    
    *secret_buf = calloc(keysize+1+pagesize, 1);
    if (!*secret_buf) {
        printf("ERROR: Malloc failure. Exiting\n");
        exit(-1);
    }
    
    /* mlock() may require that address be a multiple of PAGESIZE */
    *key = (uint8_t *)((((intptr_t)secret_buf + pagesize - 1) / pagesize) * pagesize);

    if (mlock(*key, keysize+1) != 0) {
        printf("ERROR: Mlock failure. Exiting\n");
        exit(-1);
    }
    get_random_bytes(*key, keysize);    
    return;
}

// Used to securely dispose the secrets, and unlock memory
void free_secure_random_key(uint8_t** key, uint8_t** secret_buf, size_t keysize)
{
    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize == -1) {
        printf("ERROR: Page size is reported as -1. Exiting\n");
        exit(-1);
    }
    if (munlock(*key, keysize+1) != 0) {
        printf("ERROR: Mlock failure. Exiting\n");
        exit(-1);
    }
    *key = NULL;
    // per MEM03-C clear sensitive information in buffers. 
    // params->key is inside the secret_buf, so setting that to null is sufficient.
    memset(*secret_buf, '\0', keysize+1+pagesize);
    free(*secret_buf);
    *secret_buf = NULL;
}

// Frees the AES parameters structure
void free_aes_params(aes_params_t* params)
{
    assert(valid_pointer(params) != 0);
	free_secure_random_key(&params->key, &params->key_area, params->key_size);
	free(params);
    params = NULL;
}

// Initializes AES parameters with secure defaults
aes_params_t* init_aes_params()
{
	// set sane defaults.
	aes_params_t* param = calloc(1, sizeof(aes_params_t));
    if (param == NULL) {
        printf("Fatal error!. Malloc failed, crash.\n");
        exit(-1);
    }
    // Default to 256 bit keys, and CTR Mode
	param->key_size = AES_256_BIT;
	param->aes_mode = AES_MODE_CTR;
	param->Nk = AES_256_BIT/WORD_SIZE;
	param->key = NULL;
    param->key_area = NULL;
	return param;
}

// Securely generate a key, and store in params->key
void set_aes_key(aes_params_t* param, aes_key_size_t key_size)
{
    assert(valid_pointer(param) != 0);
	param->key_size = key_size;
	param->Nk = key_size/WORD_SIZE;
    generate_secure_random_key(&param->key, &param->key_area, key_size);
}

// used to switch between AES modes of operation
void set_aes_mode(aes_params_t* param, aes_modes_t mode)
{
    assert(valid_pointer(param) != 0);
	param->aes_mode = mode;
}

// Pseudo - constant time Sbox access function
uint8_t get_sbox_value(uint8_t val) 
{
    size_t i;
    int b;
    uint8_t ret = sbox[0];
    for (i = 1; i < (BLOCK_SIZE * BLOCK_SIZE); i++) {
        // we need a function, instead of a simple comparision because the compiler might optimize this
        b = check_equality(i, (size_t)val);
        copy_byte(&ret, &sbox[i], b);
    }
    return ret;
}

// return sbox substituted word given a input 
void sub_word(uint8_t* input) 
{
    assert(valid_pointer(input) != 0);
    uint8_t temp[WORD_SIZE];
    for (int i = 0; i < WORD_SIZE; i++) {
        temp[i] = get_sbox_value(input[i]);
    }
    memcpy(input, temp, WORD_SIZE);
}

// Rotate word one byte to the left
void rot_word(uint8_t* input) 
{
    assert(valid_pointer(input) != 0);
    uint8_t temp[WORD_SIZE] = {0x00};
    temp[0] = input[1];
    temp[1] = input[2];
    temp[2] = input[3];
    temp[3] = input[0];
    memcpy(input, temp, WORD_SIZE);
}


// Returns Round Constant given any index. 
uint8_t getRcon(int idx)
{
    uint8_t rc[11] = {0x01};
    for (int r = 1; r <= idx;  r++) 
    {
        rc[r] = xtime(rc[r-1]);
    }
    return rc[idx];
}

// Key expansion routine as described in the standard
void expand_key(uint8_t* key, uint8_t Nk, uint8_t* expanded_key)
{
    assert(valid_pointer(key) != 0);
    assert(valid_pointer(expanded_key) != 0);
    uint8_t i = 0;
    uint8_t temp[WORD_SIZE] = {0x00};
    uint8_t rcon_key[WORD_SIZE] = {0x00};
    int Nk_bytes = Nk * WORD_SIZE;
    int Nr = getNr(Nk);

    if (Nr < 0 ) {
        printf("Fatal Error., invalid keysize\n");
        return;
    }

    while ( i <  WORD_SIZE * Nk ) {
        temp [0] = key[i];
        temp [1] = key[i + 1];
        temp [2] = key[i + 2];
        temp [3] = key[i + 3];
        memcpy(expanded_key + i , temp, WORD_SIZE);
        i += WORD_SIZE;
    }

    i = Nk;
    while (i < Nb * (Nr + 1)) {
            int j = i * WORD_SIZE;
            memcpy(temp, expanded_key + j - WORD_SIZE ,WORD_SIZE);
            if (i % Nk == 0) { 
                rot_word(temp);
                sub_word(temp);
                rcon_key[0] = getRcon(i/Nk);
                Xor(temp, rcon_key, WORD_SIZE);
            }
            else if ((Nk > 6) &&  (i % Nk == WORD_SIZE)) {
                sub_word(temp);
            }
            xor_with_return(expanded_key + j - Nk_bytes, temp, expanded_key + j, WORD_SIZE);
            i = i + 1;
    }
}

void sub_bytes(uint8_t (*in)[WORD_SIZE]) 
{
    assert(valid_pointer(in) != 0);
    for (int i = 0; i < WORD_SIZE; i++) {
        for (int j = 0; j < WORD_SIZE; j++) {
            in[i][j] = get_sbox_value(in[i][j]);
        }
    }
}

void shift_rows(uint8_t (*in)[WORD_SIZE]) 
{
    assert(valid_pointer(in) != 0);
    uint8_t temp = 0x00;
    temp = in[1][0];
    in[1][0] = in[1][1];
    in[1][1] = in[1][2];
    in[1][2] = in[1][3];
    in[1][3] = temp;

    // Swap [2][0] and [2][2]
    temp = in[2][0];
    in[2][0] = in[2][2];
    in[2][2] = temp;

    // Swap [2][1] and [2][3]
    temp = in[2][1];
    in[2][1] = in[2][3];
    in[2][3] = temp;

    temp = in[3][0];
    in[3][0] = in[3][3];
    in[3][3] = in[3][2]; 
    in[3][2] = in[3][1];
    in[3][1] = temp;
}

void mix_columns(uint8_t (*in)[WORD_SIZE]) 
{
    assert(valid_pointer(in) != 0);
    uint8_t old_col[WORD_SIZE] = {0x00};
    for (int i = 0; i < WORD_SIZE; i++) {
        old_col[0] = in[0][i];
        old_col[1] = in[1][i];
        old_col[2] = in[2][i];
        old_col[3] = in[3][i];
        in[0][i] = (xtime(old_col[0])) ^ (xtime(old_col[1]) ^ old_col[1]) ^ old_col[2] ^ old_col[3];
        in[1][i] = old_col[0] ^ xtime(old_col[1]) ^ (xtime(old_col[2]) ^ old_col[2]) ^ old_col[3];
        in[2][i] = old_col[0] ^ old_col[1] ^ xtime(old_col[2]) ^ (xtime(old_col[3]) ^ old_col[3]);
        in[3][i] = (xtime(old_col[0]) ^ old_col[0]) ^ old_col[1] ^ old_col[2] ^ xtime(old_col[3]);
    }
}

// AES Ciher function
void cipher(uint8_t* in, uint8_t* out, uint8_t* expanded_key, int Nk)
{
    assert(valid_pointer(in) != 0);
    assert(valid_pointer(out) != 0);
    assert(valid_pointer(expanded_key) != 0);
    uint8_t state[WORD_SIZE][WORD_SIZE] = {{0x00}};
    uint8_t temp[BLOCK_SIZE] = {0x00}; 
    memcpy(temp, expanded_key, BLOCK_SIZE);
    uint8_t roundKey[WORD_SIZE][WORD_SIZE] = {{0x00}};
    convert_to_matrix(in, state);
    convert_to_matrix(temp, roundKey);
    add_round_key(state, roundKey);
    
    int Nr = getNr(Nk);
    if (Nr < 0) {
        printf("Nr is negative. Aborting\n");
        abort();
    }
    int round;

    for (round = 1; round < Nr; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        memcpy(temp, expanded_key + (round * WORD_SIZE * WORD_SIZE), BLOCK_SIZE);
        convert_to_matrix(temp, roundKey);
        add_round_key(state, roundKey);
    }
    sub_bytes(state);
    shift_rows(state);
    memcpy(temp, expanded_key + (Nr * WORD_SIZE * WORD_SIZE), BLOCK_SIZE);
    convert_to_matrix(temp, roundKey);
    add_round_key(state, roundKey);
    convert_to_array(state, out);
}
