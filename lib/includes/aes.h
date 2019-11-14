#ifndef AES_H
#define AES_H
#include <stdint.h>
typedef enum {
    AES_MODE_CBC = 0,
    AES_MODE_ECB = 1,
    AES_MODE_CTR = 2,
    AES_MODE_OFB = 3,
    AES_MODE_CFB = 4,
} aes_modes_t;

typedef enum {
    AES_128_BIT = 16,
    AES_192_BIT = 24,
    AES_256_BIT = 32
} aes_key_size_t;

typedef struct {
    aes_modes_t aes_mode;
    aes_key_size_t key_size;
    uint8_t Nk;
    uint8_t* key;
    uint8_t* key_area;
} aes_params_t;

// Always call init parameters first
// All header functions are compliant with API08-C
aes_params_t* init_aes_params();
void free_aes_params(aes_params_t* /* param */);
void set_aes_key(aes_params_t* /* param */, aes_key_size_t /* key_size */);
void SubWord(uint8_t* /* input */);
void RotWord(uint8_t* /* input */);
void expand_key(uint8_t* /* key */, uint8_t /* Nk */, uint8_t* /* expanded_key */);
void cipher(uint8_t* /* in */, uint8_t* /* out */, uint8_t* /* w */, int /* Nk */);
void inv_cipher(uint8_t* /* in */, uint8_t* /* out */, uint8_t* /* expanded_key */, int /* Nk */);
#endif
