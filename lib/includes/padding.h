// Don't add _ before include guards - DCL37-C in SEI guide
#ifndef PADDING_H
#define PADDING_H
#include <stdint.h>
#include <sys/types.h>
// Takes input un-padded string and a output buffer. will be malloc'ed inside the code.
// Returns the length of padded string
size_t add_padding(uint8_t* /* messagebuf */, uint8_t** /* output_buf */, int /* input_msglen */);
size_t strip_padding(uint8_t* /* padbuf */, uint8_t** /* output_buf */, int /* buflen */);
#endif
