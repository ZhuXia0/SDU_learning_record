#include"padding.h"

int encrypt_ecb(const unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char** ciphertext, int* ciphertext_len) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_ecb());

    // Allocate memory for ciphertext, including padding
    *ciphertext = (unsigned char*)malloc(plaintext_len + block_size);
    if (*ciphertext == NULL) return 0;

    // Apply PKCS7 padding
    int padded_len = plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_ecb());
    unsigned char* padded_plaintext = (unsigned char*)malloc(padded_len);
    if (!padded_plaintext) return 0;

    PKCS7_Padding((unsigned char*)plaintext, plaintext_len, block_size, padded_plaintext);

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize the encryption operation.
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))
        handleErrors();

    // Provide the message to be encrypted, and obtain the encrypted output.
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, (unsigned char*)plaintext, padded_len))
        handleErrors();
    *ciphertext_len = len;

    // Finalize the encryption. Further ciphertext bytes may be written at
    // this stage.
    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) handleErrors();
    *ciphertext_len += len;
    free(padded_plaintext);
    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

int decrypt_ecb(const unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char** plaintext, int* plaintext_len) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_ecb());

    // Allocate memory for plaintext
    *plaintext = (unsigned char*)malloc(ciphertext_len);
    if (*plaintext == NULL) return 0;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize the decryption operation.
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))
        handleErrors();

    // Provide the message to be decrypted, and obtain the plaintext output.
    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    *plaintext_len = len;

    // Finalize the decryption. Further plaintext bytes may be written at
    // this stage.
    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) handleErrors();
    *plaintext_len += len;

    // Remove PKCS7 padding
    int padding = *plaintext[*plaintext_len - 1];
    *plaintext_len -= padding;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}
