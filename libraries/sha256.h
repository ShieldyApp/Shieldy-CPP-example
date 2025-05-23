#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32 // SHA256 outputs a 32-byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char SHA256_BYTE;  // 8-bit byte
typedef unsigned int  SHA256_WORD;  // 32-bit word, change to "long" for 16-bit machines

typedef struct {
    SHA256_BYTE data[64];
    SHA256_WORD datalen;
    unsigned long long bitlen;
    SHA256_WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const SHA256_BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, SHA256_BYTE hash[]);

#endif // SHA256_H
