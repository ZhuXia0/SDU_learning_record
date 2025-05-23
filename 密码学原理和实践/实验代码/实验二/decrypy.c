#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/applink.c>

#define BUFFER_SIZE 8192
#define KEY_LENGTH 32  // AES-256 requires 32 bytes
#define IV_SIZE 16
#define RSA_KEY_BITS 2048
#define ENCRYPTED_KEY_LENGTH (RSA_KEY_BITS / 8) // 256 bytes for RSA-2048
#define HMAC_LENGTH EVP_MAX_MD_SIZE  // HMAC length
#define HMAC_FILENAME "hmac_data.bin" // HMAC 文件名
#define HMAC_KEY_FILENAME "hmac_key.bin" // HMAC 密钥文件名

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Decrypt symmetric key using RSA private key
int rsa_decrypt_key(const char* private_key_file, unsigned char* encrypted_key, size_t encrypted_key_len, unsigned char* decrypted_key, size_t* decrypted_key_len) {
    FILE* priv_file = fopen(private_key_file, "rb");
    if (!priv_file) {
        fprintf(stderr, "Failed to open private key file\n");
        return -1;
    }

    EVP_PKEY* private_key = PEM_read_PrivateKey(priv_file, NULL, NULL, NULL);
    fclose(priv_file);
    if (!private_key) {
        fprintf(stderr, "Failed to read private key\n");
        handle_errors();
        return -1;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create PKEY context\n");
        handle_errors();
        EVP_PKEY_free(private_key);
        return -1;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize decryption context\n");
        handle_errors();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    // First call to EVP_PKEY_decrypt() to determine the buffer length
    size_t out_len = *decrypted_key_len;
    if (EVP_PKEY_decrypt(ctx, NULL, &out_len, encrypted_key, encrypted_key_len) <= 0) {
        fprintf(stderr, "Failed to determine buffer length\n");
        handle_errors();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    *decrypted_key_len = out_len;  // Set the output length
    if (EVP_PKEY_decrypt(ctx, decrypted_key, decrypted_key_len, encrypted_key, encrypted_key_len) <= 0) {
        fprintf(stderr, "Failed to decrypt key\n");
        handle_errors();
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);
    return 0;
}

// Function to print key in hex
void print_key_hex(unsigned char* key, size_t key_len) {
    for (size_t i = 0; i < key_len; ++i) {
        printf("%02x", key[i]);
    }
    printf("\n");
}

// Read HMAC key from file
int read_hmac_key(const char* filename, unsigned char* hmac_key, size_t key_len) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open HMAC key file\n");
        return -1;
    }

    if (fread(hmac_key, 1, key_len, file) != key_len) {
        fprintf(stderr, "Failed to read HMAC key\n");
        fclose(file);
        return -1;
    }

    fclose(file);

    // Print the HMAC key in hex format
    printf("HMAC Key: ");
    print_key_hex(hmac_key, key_len);

    return 0;
}

// Verify HMAC
int verify_hmac(const char* input_filename, unsigned char* hmac_key, size_t hmac_key_len, const unsigned char* decrypted_data, size_t data_len) {
    unsigned char calculated_hmac[HMAC_LENGTH];
    unsigned int calculated_hmac_len = 0;

    // Calculate HMAC on the decrypted data
    HMAC(EVP_sha256(), hmac_key, hmac_key_len, decrypted_data, data_len, calculated_hmac, &calculated_hmac_len);

    // Read the stored HMAC
    FILE* hmac_file = fopen(HMAC_FILENAME, "rb");
    if (!hmac_file) {
        fprintf(stderr, "Failed to open HMAC file\n");
        return -1;
    }

    unsigned char stored_hmac[HMAC_LENGTH];
    size_t stored_hmac_len = fread(stored_hmac, 1, HMAC_LENGTH, hmac_file);
    fclose(hmac_file);

    // Compare HMACs
    if (stored_hmac_len != calculated_hmac_len || memcmp(stored_hmac, calculated_hmac, stored_hmac_len) != 0) {
        fprintf(stderr, "HMAC verification failed\n");
        return -1; // HMACs do not match
    }

    return 0; // HMAC verified successfully
}

// Decrypt file
int decrypt_file(const char* encrypted_filename, const char* output_filename, const char* private_key_file) {
    FILE* encrypted_file = fopen(encrypted_filename, "rb");
    if (!encrypted_file) {
        fprintf(stderr, "Failed to open encrypted file\n");
        return -1;
    }

    FILE* output_file = fopen(output_filename, "wb");
    if (!output_file) {
        fprintf(stderr, "Failed to open output file\n");
        fclose(encrypted_file);
        return -1;
    }

    // Read the IV
    unsigned char iv[IV_SIZE];
    if (fread(iv, 1, IV_SIZE, encrypted_file) != IV_SIZE) {
        fprintf(stderr, "Failed to read IV\n");
        fclose(encrypted_file);
        fclose(output_file);
        return -1;
    }

    // Read the encrypted key length and the encrypted key
    size_t encrypted_key_len;
    if (fread(&encrypted_key_len, sizeof(size_t), 1, encrypted_file) != 1) {
        fprintf(stderr, "Failed to read encrypted key length\n");
        fclose(encrypted_file);
        fclose(output_file);
        return -1;
    }

    unsigned char encrypted_key[ENCRYPTED_KEY_LENGTH];
    if (fread(encrypted_key, 1, encrypted_key_len, encrypted_file) != encrypted_key_len) {
        fprintf(stderr, "Failed to read encrypted key\n");
        fclose(encrypted_file);
        fclose(output_file);
        return -1;
    }

    // Decrypt the symmetric key
    unsigned char decrypted_key[KEY_LENGTH];
    size_t decrypted_key_len = KEY_LENGTH;
    if (rsa_decrypt_key(private_key_file, encrypted_key, encrypted_key_len, decrypted_key, &decrypted_key_len) != 0) {
        fclose(encrypted_file);
        fclose(output_file);
        return -1;
    }

    // Print the decrypted symmetric key in hex format
    printf("Decrypted Symmetric Key: ");
    print_key_hex(decrypted_key, decrypted_key_len);

    // Read HMAC key
    unsigned char hmac_key[KEY_LENGTH]; // Adjust size as needed
    if (read_hmac_key(HMAC_KEY_FILENAME, hmac_key, KEY_LENGTH) != 0) {
        fclose(encrypted_file);
        fclose(output_file);
        return -1;
    }

    // Initialize the AES decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create decryption context\n");
        fclose(encrypted_file);
        fclose(output_file);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, decrypted_key, iv) != 1) {
        fprintf(stderr, "Failed to initialize decryption context\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(encrypted_file);
        fclose(output_file);
        return -1;
    }

    unsigned char in_buffer[BUFFER_SIZE];
    unsigned char out_buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int bytes_read, out_len;
    size_t total_decrypted_len = 0;

    // Decrypt the file and store the plaintext
    while ((bytes_read = fread(in_buffer, 1, BUFFER_SIZE, encrypted_file)) > 0) {
        if (EVP_DecryptUpdate(ctx, out_buffer, &out_len, in_buffer, bytes_read) != 1) {
            fprintf(stderr, "Decryption failed\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(encrypted_file);
            fclose(output_file);
            return -1;
        }
        fwrite(out_buffer, 1, out_len, output_file);
        total_decrypted_len += out_len;
    }

    if (EVP_DecryptFinal_ex(ctx, out_buffer, &out_len) != 1) {
        fprintf(stderr, "Final decryption step failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(encrypted_file);
        fclose(output_file);
        return -1;
    }
    fwrite(out_buffer, 1, out_len, output_file);
    total_decrypted_len += out_len;

    EVP_CIPHER_CTX_free(ctx);
    fclose(encrypted_file);
    fclose(output_file);

    printf("Decryption successful\n");

    // Verify HMAC after decryption
    unsigned char* decrypted_data = (unsigned char*)malloc(total_decrypted_len);
    if (!decrypted_data) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    // Reopen the output file to read the decrypted data
    output_file = fopen(output_filename, "rb");
    if (!output_file) {
        fprintf(stderr, "Failed to open output file for reading\n");
        free(decrypted_data);
        return -1;
    }

    fread(decrypted_data, 1, total_decrypted_len, output_file);
    fclose(output_file);

    // Verify HMAC using the decrypted data
    if (verify_hmac(encrypted_filename, hmac_key, KEY_LENGTH, decrypted_data, total_decrypted_len) != 0) {
        free(decrypted_data);
        return -1;
    }

    free(decrypted_data);
    printf("HMAC verification successful\n");
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <encrypted file> <output file> <private key file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char* encrypted_file = argv[1];
    const char* output_file = argv[2];
    const char* private_key_file = argv[3];

    if (decrypt_file(encrypted_file, output_file, private_key_file) != 0) {
        perror("Decryption failed");
        exit(EXIT_FAILURE);
    }

    return 0;
}