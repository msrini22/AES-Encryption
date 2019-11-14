#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "aes.h"
#include "lib_aes.h"
#include "utils.h"
#include "padding.h"

// CTR mode decryption
size_t aes_ctr_mode_decrypt(uint8_t* input, uint8_t** output, uint8_t Nk, uint8_t* expanded_key, int input_length) 
{
    uint8_t iv[BLOCK_SIZE] = {0x00};

    // IV is in the first 16 bytes of the cipher text
    memcpy(iv, input, BLOCK_SIZE);

    // The last 8 bytes of IV contain the starting ctr
    uint64_t ctr = 0;
    memcpy(&ctr, iv+8, 8);
    int block_size = (input_length / BLOCK_SIZE);
    int last_block_size = input_length % BLOCK_SIZE;
    uint8_t temp_op[BLOCK_SIZE] = {0x00};
    uint8_t block[BLOCK_SIZE] = {0x00};
    size_t output_length = 0;
    // The first block is the IV
    for (int i = 1; i < block_size; i++) {
        // encrypt the IV
        cipher(iv, temp_op, expanded_key, Nk);
        // Increment the counter;
        ctr++;
        // copy the ctr into the last 8 bytes of the IV
        memcpy(iv + 8, &ctr, 8);

        // Xor the results of the encryption with the block of cipher text
        memcpy(block, input + (i * BLOCK_SIZE), BLOCK_SIZE);
        Xor(temp_op, block, BLOCK_SIZE);
        memcpy(*output + ((i - 1) * BLOCK_SIZE), temp_op, BLOCK_SIZE);
        output_length++;
    }
    // Handle the last incomplete block here
    cipher(iv, temp_op, expanded_key, Nk);
    // Xor the results of the encryption with the block of cipher text
    memcpy(block, input + (block_size * BLOCK_SIZE), last_block_size);
    Xor(temp_op, block, last_block_size);
    memcpy(*output + ((block_size - 1) * BLOCK_SIZE), temp_op, last_block_size);

    return output_length * BLOCK_SIZE + last_block_size;
}

//OFB decryption
size_t aes_ofb_mode_decrypt(uint8_t* input, uint8_t** output, uint8_t Nk, uint8_t* expanded_key, int input_length) 
{
    uint8_t iv[BLOCK_SIZE] = {0x00};
    // IV is in the first 16 bytes of the cipher text
    memcpy(iv, input, BLOCK_SIZE);
    int block_size = (input_length / BLOCK_SIZE);
    int last_block_size = input_length % BLOCK_SIZE;

    uint8_t temp_op[BLOCK_SIZE] = {0x00};
    uint8_t block[BLOCK_SIZE] = {0x00};
    size_t output_length = 0;
    // The first block is the IV
    for (int i = 1; i < block_size; i++) {
        // encrypt the IV
        cipher(iv, temp_op, expanded_key, Nk);
        // copy the output of encryption as the next IV
        memcpy(iv, temp_op, BLOCK_SIZE);
        // Xor the results of the encryption with the block of cipher text
        memcpy(block, input + (i * BLOCK_SIZE), BLOCK_SIZE);
        Xor(temp_op, block, BLOCK_SIZE);
        memcpy(*output + ((i - 1) * BLOCK_SIZE), temp_op, BLOCK_SIZE);
        output_length++;
    }
    // Handle the last incomplete block here
    cipher(iv, temp_op, expanded_key, Nk);
    // Xor the results of the encryption with the `last_block_size` bytes cipher text
    memcpy(block, input + (block_size * BLOCK_SIZE), last_block_size);
    Xor(temp_op, block, last_block_size);
    memcpy(*output + ((block_size - 1) * BLOCK_SIZE), temp_op, last_block_size);

    return (output_length * BLOCK_SIZE)+ last_block_size;
}

// Uses CFB in 128 bit mode
size_t aes_cfb_mode_decrypt(uint8_t* input, uint8_t** output, uint8_t Nk, uint8_t* expanded_key, int input_length) 
{
    uint8_t iv[BLOCK_SIZE] = {0x00};
    // IV is in the first 16 bytes of the cipher text
    memcpy(iv, input, BLOCK_SIZE);
    int block_size = (input_length / BLOCK_SIZE);
    int last_block_size = input_length % BLOCK_SIZE;
    uint8_t temp_op[BLOCK_SIZE] = {0x00};
    uint8_t block[BLOCK_SIZE] = {0x00};
    size_t output_length = 0;
    // The first block is the IV
    for (int i = 1; i < block_size; i++) {
        // encrypt the IV
        cipher(iv, temp_op, expanded_key, Nk);
        memcpy(block, input + (i * BLOCK_SIZE), BLOCK_SIZE);
        Xor(temp_op, block, BLOCK_SIZE);
        memcpy(*output + ((i - 1) * BLOCK_SIZE), temp_op, BLOCK_SIZE);
        memcpy(iv, block, BLOCK_SIZE);
        output_length++;
    }
    // Handle the last incomplete block here. 
    cipher(iv, temp_op, expanded_key, Nk);
    memcpy(block, input + (block_size * BLOCK_SIZE), last_block_size);
    Xor(temp_op, block, last_block_size);
    memcpy(*output + ((block_size - 1) * BLOCK_SIZE), temp_op, last_block_size);
    return (output_length * BLOCK_SIZE)+ last_block_size;
}

// ECB decryption - Returns length of decrypted message
size_t aes_ecb_mode_decrypt(uint8_t* input, uint8_t** output, uint8_t Nk, uint8_t* expanded_key, int input_length) 
{
    uint8_t block[BLOCK_SIZE] = {0x00};
    uint8_t temp_op[BLOCK_SIZE] = {0x00};
    size_t output_length = 0;
    int block_size = (input_length / BLOCK_SIZE);
    // The first block is the IV
    for (int i = 0; i < block_size; i++) {
        memcpy(block, input + (i * BLOCK_SIZE), BLOCK_SIZE);
        inv_cipher(block, temp_op, expanded_key, Nk);
        memcpy(*output + (i * BLOCK_SIZE), temp_op, BLOCK_SIZE);
        output_length++;
    }
    return output_length * BLOCK_SIZE;
}

// CBC- Decrypt: Returns length of decrypted message
size_t aes_cbc_mode_decrypt(uint8_t* input, uint8_t** output, uint8_t Nk, uint8_t* expanded_key, int input_length) 
{
    uint8_t iv[BLOCK_SIZE] = {0x00};
    // IV is in the first 16 bytes of the cipher text
    memcpy(iv, input, BLOCK_SIZE);
    int block_size = (input_length / BLOCK_SIZE);
    uint8_t block[BLOCK_SIZE] = {0x00};
    uint8_t temp_op[BLOCK_SIZE] = {0x00};
    size_t output_length = 0;
    // The first block is the IV
    for (int i = 1; i < block_size; i++) {
        memcpy(block, input + (i*BLOCK_SIZE), BLOCK_SIZE);
        inv_cipher(block, temp_op, expanded_key, Nk);
        Xor(temp_op, iv, BLOCK_SIZE);
        memcpy(*output + ((i - 1) * BLOCK_SIZE), temp_op, BLOCK_SIZE);
        memcpy(iv,block,BLOCK_SIZE);
        output_length++;
    }
    return output_length * BLOCK_SIZE;
}

// Decryption driver method
size_t decrypt(aes_params_t* aes_params, uint8_t* input, uint8_t** output, int input_length)
{
    assert(valid_pointer(aes_params) != 0);
    assert(valid_pointer(input) != 0);
    int Nr = getNr(aes_params->Nk);
    // the last *4 is to convert words to bytes
    int len = 4 * (Nr + 1) * 4;
    uint8_t expanded_key[len]; 
    expand_key(aes_params->key, aes_params->Nk, expanded_key);
    size_t output_length = 0;
    uint8_t* padded_op = NULL;
    bool strip_padding_bytes = true;
    switch(aes_params->aes_mode) {
        case AES_MODE_CBC:
            // Padded output string will be 16 bytes less than the input (for the IV)
            // Calloc instead of Malloc to zero initialize memory
            // Add one byte for null termination at the end
            strip_padding_bytes = true;
            padded_op = calloc(input_length - BLOCK_SIZE + 1, 1);
            if (NULL == padded_op) {
                printf("FATAL ERROR: Calloc failure\n");
                exit(-1);
            }
            output_length = aes_cbc_mode_decrypt(input, &padded_op, aes_params->Nk, expanded_key, input_length);
            break;
        case AES_MODE_ECB:
            strip_padding_bytes = true;
            padded_op = calloc(input_length + 1, 1);
            if (NULL == padded_op) {
                printf("FATAL ERROR: Calloc failure\n");
                exit(-1);
            }
            output_length = aes_ecb_mode_decrypt(input, &padded_op, aes_params->Nk, expanded_key, input_length);
            break;
        case AES_MODE_CFB:
            strip_padding_bytes = true;
            padded_op = calloc(input_length + 1, 1);
            if (NULL == padded_op) {
                printf("FATAL ERROR: Calloc failure\n");
                exit(-1);
            }
            output_length = aes_cfb_mode_decrypt(input, &padded_op, aes_params->Nk, expanded_key, input_length);
            break;
        case AES_MODE_CTR:
            strip_padding_bytes = false;
            // add one byte for null character
            *output = calloc(input_length - BLOCK_SIZE + 1, 1);
            if (NULL == output) {
                printf("FATAL ERROR: Calloc failure\n");
                exit(-1);
            }
            output_length = aes_ctr_mode_decrypt(input, output, aes_params->Nk, expanded_key, input_length);
            break;
        case AES_MODE_OFB:
            strip_padding_bytes = false;
            // add one byte for null character
            *output = calloc(input_length - BLOCK_SIZE + 1, 1);
            if (NULL == output) {
                printf("FATAL ERROR: Calloc failure\n");
                exit(-1);
            }
            output_length = aes_ofb_mode_decrypt(input, output, aes_params->Nk, expanded_key, input_length);
            break;
        default:
            break;
    }

    if (strip_padding_bytes) {
        output_length = strip_padding(padded_op, output, output_length);
        free(padded_op);
        padded_op = NULL;
        return output_length;
    } else {
        return output_length;
    }
}
