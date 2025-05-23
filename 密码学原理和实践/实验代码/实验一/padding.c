//padding.c
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include<openssl/err.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

// PKCS7 padding
void PKCS7_Padding(unsigned char* input, int length, int blockSize, unsigned char* output) {
    int padding = blockSize - (length % blockSize);
    memcpy(output, input, length);
    for (int i = length; i < length + padding; i++) {
        output[i] = padding;
    }
}

void PKCS7_Trimming(unsigned char* input, int length, int blockSize, unsigned char* output, int* outLength) {
    int padding = input[length - 1];
    *outLength = length - padding;
    memcpy(output, input, *outLength);
}