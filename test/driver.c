#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include "aes.h"
#include "lib_aes.h"
#include "utils.h"

void test_encryption(aes_key_size_t key_size, uint8_t Nk, uint8_t* input, size_t input_size)
{
    aes_params_t* params = init_aes_params();
    if (params == NULL) {
        printf("Fatal error. unable to alloc aes params\n");
        return;
    } 
    set_aes_key(params, key_size); 
    printf("The key used is\t");
    print_word(params->key, Nk * 4); 
    printf("Bytes Plain: \t");
    print_word(input, input_size);
    printf("Input: \t%s\n", input);
    
    uint8_t* output = NULL; 
    size_t enc_len = encrypt(params, input, &output, input_size);
    printf("Encrypted Bytes: \t");
    print_word(output, enc_len);

    uint8_t* plain = NULL;
    size_t dec_len = decrypt(params, output, &plain, enc_len);
    // Null terminate the string
    plain[dec_len] = '\0';
    printf("Decrypted bytes: \t");
    print_word(plain, dec_len);
    printf("Decrypted String: \t%s\n", plain);
    free(output);
    free(plain);
    free_aes_params(params);
    output = NULL;
    plain = NULL;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
	    printf("Error, enter a value to encrypt!\n");
    	return -1;
    }
    size_t input_size = strlen(argv[1]);
    
    uint8_t* input = NULL;
    input = calloc(input_size + 1, 1);
    if (input == NULL) {
        printf("fatal error, Calloc failure");
        exit(-1);
    }

    memcpy(input, argv[1], input_size);
    input[input_size] = '\0';
    printf("128 - Bit AES\n");
    test_encryption(AES_128_BIT, 4, input, input_size); 
    printf("192 - Bit AES\n");
    test_encryption(AES_192_BIT, 6, input, input_size); 
    printf("256 - Bit AES - \n");
    test_encryption(AES_256_BIT, 8, input, input_size); 
    free(input);
    return 0;
}
