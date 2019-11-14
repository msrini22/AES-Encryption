#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "padding.h"
#include "utils.h"

// Add the padding to a given buffer
size_t add_padding(uint8_t* messagebuf, uint8_t **output_buf, int input_msglen)
{
    assert(valid_pointer(messagebuf) != 0);
    size_t bytestopad = BLOCK_SIZE;

    if ((input_msglen % BLOCK_SIZE) == 0) {
        bytestopad = BLOCK_SIZE;
    } else {
        bytestopad = BLOCK_SIZE - (input_msglen % BLOCK_SIZE);
    }

    *output_buf = calloc(input_msglen + BLOCK_SIZE, 1);
    if (NULL == output_buf) {
        printf("FATAL ERROR: Calloc failure\n");
        exit(-1);
    }
    memcpy(*output_buf, messagebuf, input_msglen);
    memset(*output_buf + input_msglen, bytestopad, bytestopad);
    return input_msglen + bytestopad;
}

// Compliant with API02 - C
// Throws no errors on padding errors - preventing padding oracle attacks 
// Strips padding from the given buffer
size_t strip_padding(uint8_t* padbuf,  uint8_t **outputbuf, int buflen)
{
    assert(valid_pointer(padbuf) != 0);
    uint8_t lastbyte = padbuf[buflen - 1];
    *outputbuf = calloc(buflen - lastbyte + 1, 1); // 1 is to store the Null byte
    // Adher to ERR33-C - Handle standard library errors
    if (NULL == outputbuf) {
        printf("FATAL ERROR: Calloc failure\n");
        exit(-1);
    }
    memcpy(*outputbuf, padbuf, (buflen - lastbyte));
    return (buflen - lastbyte);
}
