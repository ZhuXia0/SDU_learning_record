#include"padding.h"

int encrypt_cbc(const unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char** ciphertext, int* ciphertext_len) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());

    // Allocate memory for ciphertext, including padding
    *ciphertext = (unsigned char*)malloc(plaintext_len + block_size);
    if (*ciphertext == NULL) return 0;

    // Apply PKCS7 padding
    int padded_len = plaintext_len + (block_size - plaintext_len % block_size);
    unsigned char* padded_plaintext = (unsigned char*)malloc(padded_len);
    if (!padded_plaintext) return 0;
    PKCS7_Padding((unsigned char*)plaintext, plaintext_len, block_size, padded_plaintext);

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize the encryption operation.
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    // Provide the message to be encrypted, and obtain the encrypted output.
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, padded_plaintext, padded_len))
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

int decrypt_cbc(const unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char** plaintext, int* plaintext_len) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());

    // Allocate memory for plaintext
    *plaintext = (unsigned char*)malloc(ciphertext_len);
    if (*plaintext == NULL) return 0;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize the decryption operation.
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    // Provide the message to be decrypted, and obtain the plaintext output.
    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();

    // Temporary length, will be corrected after trimming
    *plaintext_len = len;

    // Finalize the decryption. Further plaintext bytes may be written at
    // this stage.
    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) handleErrors();
    *plaintext_len += len;

    // Remove PKCS7 padding
    int trimmed_len;
    unsigned char* trimmed_plaintext = (unsigned char*)malloc(*plaintext_len);
    if (!trimmed_plaintext) return 0;
    PKCS7_Trimming(*plaintext, *plaintext_len, block_size, trimmed_plaintext, &trimmed_len);

    memcpy(*plaintext, trimmed_plaintext, trimmed_len);
    *plaintext_len = trimmed_len;
    free(trimmed_plaintext);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

//int main() {
//    unsigned char key[32]; // 256-bit key
//    unsigned char iv[16];  // Initialization vector for CBC mode
//
//    // Generate a random key and IV
//    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
//        printf("Error generating random bytes\n");
//        return 1;
//    }
//
//    unsigned char* plaintext = (unsigned char*)"Hello, OpenSSL CBC!";
//    int plaintext_len = strlen((char*)plaintext);
//
//    unsigned char* ciphertext = NULL;
//    int ciphertext_len;
//
//    unsigned char* decryptedtext = NULL;
//    int decryptedtext_len;
//
//    // Encrypt
//    if (!encrypt_cbc(plaintext, plaintext_len, key, iv, &ciphertext, &ciphertext_len)) {
//        printf("Encryption failed\n");
//        return 1;
//    }
//
//    printf("Ciphertext is:\n");
//    BIO_dump_fp(stdout, (const char*)ciphertext, ciphertext_len);
//
//    // Decrypt
//    if (!decrypt_cbc(ciphertext, ciphertext_len, key, iv, &decryptedtext, &decryptedtext_len)) {
//        printf("Decryption failed\n");
//        return 1;
//    }
//
//    decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted text
//    printf("Decrypted text is:\n");
//    printf("%s\n", decryptedtext);
//
//
//    return 0;
//}