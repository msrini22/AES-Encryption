#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/random.h>
#include <fcntl.h>
#include "utils.h"

// Utility function to print a byte string of any length
void print_word(uint8_t* word, int len) 
{
    assert(valid_pointer(word) != 0);
    for (int i = 0; i < len; i++) {
        printf("%02x", word[i]); 
    }
    printf("\n\n");
}

// Utilty function that Xors A and B and stores result in A
void Xor(uint8_t* input, uint8_t* val, int length)
{
    assert(valid_pointer(input) != 0);
    assert(valid_pointer(val) != 0);
	for (int i = 0; i < length; i++) {
		input[i] = input[i] ^ val[i];
	}
}
// Utility function that Xors A and B and stores result in Val
void xor_with_return(uint8_t* input, uint8_t* val, uint8_t* ret, int length)
{
    assert(valid_pointer(input) != 0);
    assert(valid_pointer(val) != 0);
    assert(valid_pointer(ret) != 0);
	for (int i = 0; i < length; i++) {
    	ret[i] = input[i] ^ val[i];
    }
}

// Returns Nr given a Nk
int getNr(int Nk)
{
    if (Nk == 4) 
    {
        return 10;
    }
    else if (Nk == 6)
    {
        return 12;
    }
    else if (Nk == 8)
    {
        return 14;
    }
    return -1;
}

// Utility function to dump a 4 * 4 matrix
void dump_matrix(uint8_t inp[WORD_SIZE][WORD_SIZE]) 
{
    for (int i = 0; i < WORD_SIZE; i++) {
        for (int j = 0; j < WORD_SIZE; j++) {
            printf("%02x\t", inp[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

// Utility function that converts a array to a matrix
void convert_to_matrix(uint8_t* in, uint8_t (*out)[WORD_SIZE])
{
    assert(valid_pointer(in) != 0);
    assert(valid_pointer(out) != 0);
    int k = 0;
    for (int i = 0; i < WORD_SIZE; i++) {
        for (int j = 0; j < WORD_SIZE; j++) {
            out[j][i] = in[k];
            k++;
        }
    }   
}

// Utility function that converts a matrix to an array
void convert_to_array(uint8_t(*in)[WORD_SIZE], uint8_t* out)
{
    assert(valid_pointer(in) != 0);
    assert(valid_pointer(out) != 0);
    int k = 0;
    for (int i = 0; i < WORD_SIZE; i++) {
        for (int j = 0; j < WORD_SIZE; j++) {
            out[k] = in[j][i];
            k++;
        }
    }   
}

// Xtime or multiply by two in GF(8)
uint8_t xtime(uint8_t val)
{
  return ((val << 1) ^ (((val >> 7) & 1) * 0x1b));
}

// Adds the given round key to the state matrix
void add_round_key(uint8_t (*in)[WORD_SIZE], uint8_t (*w)[WORD_SIZE]) 
{
    //MEM10-C: check pointer validity
    assert(valid_pointer(in) != 0);
    assert(valid_pointer(w) != 0);
    for (int i = 0; i < WORD_SIZE; i++) {
        for (int j = 0; j < WORD_SIZE; j++) {
            in[i][j] = in[i][j] ^ w[i][j];    
        }
    }
}

// The reads /dev/urandom and returns 'size' random bytes stored in 'result'.
void get_random_bytes(uint8_t* result, size_t size)
{
    //always check if the pointer is valid
    assert(valid_pointer(result) != 0);
    // This is non-blocking, and a CPRNG.
    // A popular myth is that /dev/random is `safer` than /dev/urandom, but its not the case.
    // This is the recommended method of fetchig random bytes. It is safe to read upto 32mb of data
    // in one shot from /dev/urandom
    // implement POS01-C: Prevent following symlinks
    int fd = open("/dev/urandom", O_NOFOLLOW | O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        printf("Error opening /dev/urandom. Aborting \n");
        abort();
    }
	struct stat st;

    // Verify that the device node is a special character device (/dev/urandom is one)
    if (fstat(fd, &st) == -1 || !S_ISCHR(st.st_mode)) {
        close(fd);
        printf("/dev/urandom looks fishy. Aborting\n");
        abort();
    }
    int cnt;
    // Check if we have enough entropy
    if (ioctl(fd, RNDGETENTCNT, &cnt) == -1) {
        close(fd);
        printf("Entropy not enough, aborting()\n");
        abort();
    }
    size_t bytes_read = read(fd, result, size);
    int ret = close(fd);
    assert(bytes_read == size);
    assert(ret >= 0);
}

// A Linux only method that checks validity of a pointer - defined by SEI
int valid_pointer(void *p)
{
  extern char _etext;
  return (p != NULL) && ((char*) p > &_etext);
}

// Copy byte from a to r, based on b's bitmask. 
void copy_byte(uint8_t *r, const uint8_t *a, uint32_t b)
{
    uint8_t t;
    b = -b; /* Now b is either 0 or 0xffffffff */
    t = (*r ^ *a) & b;
    *r ^= t;
}

// We need this because the compiler will optimize the normal equality checking out
int check_equality(uint32_t a, uint32_t b)
{
    size_t i; 
    uint32_t r = 0;
    unsigned char *ta = (unsigned char *)&a;
    unsigned char *tb = (unsigned char *)&b;
    for(i=0;i<sizeof(uint32_t);i++)
    {
        r |= (ta[i] ^ tb[i]);
    }
    r = (-r) >> 31;
    return (int)(1-r);
}
