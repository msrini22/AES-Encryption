// Don't add _ before include guards - DCL37-C in SEI guide
#ifndef UTIL_H
#define UTIL_H
#include <stdint.h>
#include <assert.h>
#define BLOCK_SIZE 16
#define WORD_SIZE 4
int getNr(int /* Nk */);
void Xor(uint8_t* /* input */, uint8_t* /* val */, int /* length */);
void xor_with_return(uint8_t* /* input */, uint8_t* /* val */, uint8_t* /* ret */, int /* length */);
void add_round_key(uint8_t (*in)[WORD_SIZE], uint8_t (*w)[WORD_SIZE]);
void convert_to_matrix(uint8_t* /* in */, uint8_t (*out)[WORD_SIZE]);
void convert_to_array(uint8_t(*in)[WORD_SIZE], uint8_t* /* out */);
void dump_matrix(uint8_t /* inp */ [WORD_SIZE][WORD_SIZE]);
void print_word(uint8_t* /* word */, int /*len*/); 
uint8_t xtime(uint8_t /* val */);
void get_random_bytes(uint8_t* /* result */, size_t /* size */);
int valid_pointer(void * /* p */);
void copy_byte(uint8_t * /* r */, const uint8_t * /* a */, uint32_t /* b */);
int check_equality(uint32_t /* a */, uint32_t /* b */);

#endif
