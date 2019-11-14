// Don't add _ before include guards - DCL37-C in SEI guide
#ifndef LIB_AES_H
#define LIB_AES_H
#include "aes.h"
size_t encrypt(aes_params_t* /* aes_params */, uint8_t* /* input */, uint8_t** /* output */, int /* input_length */);
// copies a non-null terminated string into the buffer. has space for a null
// It is the responsibility of the caller to null terminate the string
size_t decrypt(aes_params_t* /* aes_params */, uint8_t* /* input */, uint8_t** /* output */, int /* input_length */);
#endif //ifndef LIB_AES_H
