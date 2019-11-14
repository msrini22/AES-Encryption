#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "lib_aes.h"
#include "padding.h"
#include "utils.h"

// Implementation of CTR mode
size_t aes_ctr_mode_encrypt(uint8_t* input, uint8_t** output, uint8_t Nk, uint8_t* expanded_key, int input_length) 
{
    int num_blocks = input_length / BLOCK_SIZE;
    int last_block_size = input_length  % BLOCK_SIZE;
    uint8_t iv[BLOCK_SIZE] = {0x00};
    uint64_t ctr = 0;
    // Get a random byte string of 128 bits
    // Use the last 64bits as the ctr
    get_random_bytes(iv, BLOCK_SIZE);
    memcpy(&ctr, iv + 8 , 8);
    uint8_t block[BLOCK_SIZE] = {0x00};
    uint8_t temp_op[BLOCK_SIZE] = {0x00};

    // IV is in the first BLOCK_SIZE bytes of the cipher text
    memcpy(*output, iv, BLOCK_SIZE);
    //to account for the IV that's appended.
    size_t output_length = 1;
    for (int i = 0; i < num_blocks; i++) {
        // First encrypt the IV
        cipher(iv, temp_op, expanded_key, Nk);
        // Increment the counter of the IV.
        ctr ++;
        // Copy the ctr to the last 8 bytes of IV
        memcpy(iv+8, &ctr, 8);
        memcpy(block, input + (i * BLOCK_SIZE), BLOCK_SIZE);
        // Xor the encrypted val with the plain text
        Xor(temp_op, block, BLOCK_SIZE);
        memcpy(*output + (i * BLOCK_SIZE) + BLOCK_SIZE, temp_op, BLOCK_SIZE);
        output_length ++;
    }
    // Deal with the last block here
    cipher(iv, temp_op, expanded_key, Nk);
    memcpy(block, input + (num_blocks * BLOCK_SIZE), last_block_size);
    // Xor the encrypted val with the plain text
    Xor(temp_op, block, last_block_size);
    memcpy(*output + (num_blocks * BLOCK_SIZE) + BLOCK_SIZE, temp_op, last_block_size);
    return (output_length * BLOCK_SIZE) + last_block_size;
}

// Implementation of OFB mode of operation
size_t aes_ofb_mode_encrypt(uint8_t* input, uint8_t** output, uint8_t Nk, uint8_t* expanded_key, int input_length) 
{
    int num_blocks = input_length / BLOCK_SIZE;
    int last_block_size = input_length % BLOCK_SIZE;
    uint8_t iv[BLOCK_SIZE] = {0x00};
    get_random_bytes(iv, BLOCK_SIZE);
    uint8_t block[BLOCK_SIZE] = {0x00};
    uint8_t temp_op[BLOCK_SIZE] = {0x00};

    // IV is in the first 16 bytes of the cipher text
    memcpy(*output, iv, BLOCK_SIZE);
    //to account for the IV that's appended.
    size_t output_length = 1;
    for (int i = 0; i < num_blocks; i++) {
        // First encrypt the IV
        cipher(iv, temp_op, expanded_key, Nk);
        // Use the encrypted value as the IV for next
        memcpy(iv, temp_op,BLOCK_SIZE);
        memcpy(block, input + (i * BLOCK_SIZE), BLOCK_SIZE);
        // Xor the encrypted val with the plain text
        Xor(temp_op, block, BLOCK_SIZE);
        memcpy(*output + (i * BLOCK_SIZE) + BLOCK_SIZE, temp_op, BLOCK_SIZE);
        output_length ++;
    }
    // Process the last incomplete block here
    cipher(iv, temp_op, expanded_key, Nk);
    memcpy(iv, temp_op, BLOCK_SIZE);
    memcpy(block, input + (num_blocks * BLOCK_SIZE), last_block_size);
    // Xor the encrypted val with the plain text
    Xor(temp_op, block, last_block_size);
    memcpy(*output + (num_blocks * BLOCK_SIZE) + BLOCK_SIZE, temp_op, last_block_size);
    
    return (output_length * BLOCK_SIZE) + last_block_size;
}

// This implements CFB with 128 bit segments
size_t aes_cfb_mode_encrypt(uint8_t* input, uint8_t** output, uint8_t Nk, uint8_t* expanded_key, int input_length) 
{
    uint8_t iv[BLOCK_SIZE] = {0x00};
    get_random_bytes(iv, BLOCK_SIZE);
    int num_blocks = input_length / BLOCK_SIZE;
    int last_block_size = input_length % BLOCK_SIZE;
    uint8_t block[BLOCK_SIZE] = {0x00};
    uint8_t temp_op[BLOCK_SIZE] = {0x00};

    // IV is in the first 16 bytes of the cipher text
    memcpy(*output, iv, BLOCK_SIZE);
    //to account for the IV that's appended.
    size_t output_length = 1;
    for (int i = 0; i < num_blocks; i++) {
        // First encrypt the IV
        cipher(iv, temp_op, expanded_key, Nk);
        // Then Xor with plain text
        // Use the result as the IV for next
        memcpy(block, input + (i * BLOCK_SIZE), BLOCK_SIZE);
        Xor(temp_op, block, BLOCK_SIZE);
        memcpy(*output + (i * BLOCK_SIZE) + BLOCK_SIZE, temp_op, BLOCK_SIZE);
        memcpy(iv, temp_op, BLOCK_SIZE);
        output_length ++;
    }
    // Handle the last incomplete block here
    cipher(iv, temp_op, expanded_key, Nk);
    // Then Xor with `last_block_size` bytes of plain text
    memcpy(block, input + (num_blocks * BLOCK_SIZE), last_block_size);
    Xor(temp_op, block, last_block_size);
    memcpy(*output + (num_blocks * BLOCK_SIZE) + BLOCK_SIZE, temp_op, last_block_size);
    
    return (output_length * BLOCK_SIZE) + last_block_size;
}

// ECB mode of operation
size_t aes_ecb_mode_encrypt(uint8_t* input, uint8_t** output, uint8_t Nk, uint8_t* expanded_key, int input_length) 
{
    int num_blocks = input_length / BLOCK_SIZE;
    uint8_t block[BLOCK_SIZE] = {0x00};
    uint8_t temp_op[BLOCK_SIZE] = {0x00};

    size_t output_length = 0;
    for (int i = 0; i < num_blocks; i++) {
        memcpy(block, input + (i * BLOCK_SIZE), BLOCK_SIZE);
        cipher(block, temp_op, expanded_key, Nk);
        memcpy(*output + (i * BLOCK_SIZE), temp_op, BLOCK_SIZE);
        output_length++;
    }
    return output_length * BLOCK_SIZE;
}

// CBC mode of operation
size_t aes_cbc_mode_encrypt(uint8_t* input, uint8_t** output, uint8_t Nk, uint8_t* expanded_key, int input_length) 
{
    uint8_t iv[BLOCK_SIZE] = {0x00};
    get_random_bytes(iv, BLOCK_SIZE);
    int num_blocks = input_length / BLOCK_SIZE;
    uint8_t block[BLOCK_SIZE] = {0x00};
    uint8_t temp_op[BLOCK_SIZE] = {0x00};

    // IV is in the first 16 bytes of the cipher text
    memcpy(*output, iv, BLOCK_SIZE);
    //to account for the IV that's appended.
    size_t output_length = 1;
    for (int i = 0; i < num_blocks; i++) {
        memcpy(block, input + (i * BLOCK_SIZE), BLOCK_SIZE);
        Xor(block, iv, BLOCK_SIZE);
        cipher(block, temp_op, expanded_key, Nk);
        // a +BLOCK_SIZE is needed because of the IV
        memcpy(*output + ( i * BLOCK_SIZE) + BLOCK_SIZE, temp_op, BLOCK_SIZE);
        memcpy(iv, temp_op, BLOCK_SIZE);
        output_length++;
    }
    return output_length * BLOCK_SIZE;
}

// The master encryption method
size_t encrypt(aes_params_t* aes_params, uint8_t* input, uint8_t** output, int input_length)
{
    assert(valid_pointer(aes_params) != 0);
    assert(valid_pointer(input) != 0);
    uint8_t* padded_input = NULL; 
    size_t output_length = 0;
    size_t padded_input_length = 0;
    
    int Nr = getNr(aes_params->Nk);
    // the last *4 is to convert words to bytes
    int len = 4 * (Nr + 1) * 4;
    uint8_t expanded_key[len]; 
    expand_key(aes_params->key, aes_params->Nk, expanded_key);
    switch(aes_params->aes_mode) {
        case AES_MODE_CBC:
            // We know that the length has to be input_length + BLOCK_SIZE (for the IV)
            // Pad the message. We don't care if the message is a multiple of BLOCK_SIZE. Always Pad.
            padded_input_length = add_padding(input, &padded_input, input_length);
            *output = calloc(padded_input_length + BLOCK_SIZE, 1);
            if (NULL == output) {
                printf("FATAL ERROR: Calloc failure\n");
                exit(-1);
            }
            output_length = aes_cbc_mode_encrypt(padded_input, output, aes_params->Nk, expanded_key, padded_input_length);
            break;
        case AES_MODE_ECB:
            // We know that the length has to be input_length
            padded_input_length = add_padding(input, &padded_input, input_length);
            *output = calloc(padded_input_length, 1);
            if (NULL == output) {
                printf("FATAL ERROR: Calloc failure\n");
                exit(-1);
            }
            output_length = aes_ecb_mode_encrypt(padded_input, output, aes_params->Nk, expanded_key, padded_input_length);
            break;
        case AES_MODE_CFB:
            padded_input_length = add_padding(input, &padded_input, input_length);
            *output = calloc(padded_input_length + BLOCK_SIZE, 1);
            if (NULL == output) {
                printf("FATAL ERROR: Calloc failure\n");
                exit(-1);
            }
            output_length = aes_cfb_mode_encrypt(padded_input, output, aes_params->Nk, expanded_key, padded_input_length);
            break;
        case AES_MODE_CTR:
            // AES with CTR mode needs no padding.
            *output = calloc(input_length + BLOCK_SIZE, 1);
            if (NULL == output) {
                printf("FATAL ERROR: Calloc failure\n");
                exit(-1);
            }
            output_length = aes_ctr_mode_encrypt(input, output, aes_params->Nk, expanded_key, input_length);
            break;
        case AES_MODE_OFB:
            // AES with OFB mode needs no padding.
            *output = calloc(input_length + BLOCK_SIZE, 1);
            if (NULL == output) {
                printf("FATAL ERROR: Calloc failure\n");
                exit(-1);
            }
            output_length = aes_ofb_mode_encrypt(input, output, aes_params->Nk, expanded_key, input_length);
            break;
        default:
            break;
    }

    // padded_input might be NULL - But its ok.!
    free(padded_input);
    // Per MEM01-C, set variables to null after free.
    padded_input = NULL;
    return output_length;
}
