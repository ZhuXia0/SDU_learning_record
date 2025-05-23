
#include"padding.h"
#include<openssl/applink.c>
int encrypt_ofb(const unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char** ciphertext, int* ciphertext_len) {
    EVP_CIPHER_CTX* ctx;
    int len;

    // Allocate memory for ciphertext (same size as plaintext for OFB)
    *ciphertext = (unsigned char*)malloc(plaintext_len);
    if (*ciphertext == NULL) return 0;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize the encryption operation.
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key, iv))
        handleErrors();

    // Provide the message to be encrypted, and obtain the encrypted output.
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    *ciphertext_len = len;

    // Finalize the encryption. For OFB, this should not write any extra bytes.
    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) handleErrors();
    // Note: For OFB, EVP_EncryptFinal_ex should always return 0 bytes written to len.
    // However, we still call it for consistency with the API usage pattern.
    // We don't add len to ciphertext_len because it should be 0.

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

int decrypt_ofb(const unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char** plaintext, int* plaintext_len) {
    EVP_CIPHER_CTX* ctx;
    int len;

    // Allocate memory for plaintext (same size as ciphertext for OFB)
    *plaintext = (unsigned char*)malloc(ciphertext_len);
    if (*plaintext == NULL) return 0;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize the decryption operation.
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key, iv))
        handleErrors();

    // Provide the message to be decrypted, and obtain the plaintext output.
    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    *plaintext_len = len;

    // Finalize the decryption. For OFB, this should not write any extra bytes.
    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) handleErrors();
    // Note: For OFB, EVP_DecryptFinal_ex should always return 0 bytes written to len.
    // However, we still call it for consistency with the API usage pattern.
    // We don't add len to plaintext_len because it should be 0.

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

