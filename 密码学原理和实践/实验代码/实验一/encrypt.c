#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/params.h>

#define BUFFER_SIZE 8192
#define KEY_LENGTH 32 // AES-256 需要 32 字节
#define IV_SIZE 16

int derive_key_from_password(const char* password, unsigned char* derived_key, size_t key_len) {
    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    if (!kdf) return -1;

    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    if (!ctx) { EVP_KDF_free(kdf); return -1; }

    unsigned char salt[] = "NaCl";
    unsigned int iterations = 80000;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string("pass", password, strlen(password)),
        OSSL_PARAM_construct_octet_string("salt", salt, strlen(salt)),
        OSSL_PARAM_construct_uint("iter", &iterations),
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(ctx, derived_key, key_len, params) != 1) {
        EVP_KDF_CTX_free(ctx);
        EVP_KDF_free(kdf);
        return -1;
    }

    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return 0;
}

int encrypt_file(const char* input_filename, const char* output_filename, unsigned char* key) {
    FILE* input_file = fopen(input_filename, "rb");
    if (!input_file) {
        perror("Failed to open input file");
        return -1;
    }

    FILE* output_file = fopen(output_filename, "wb");
    if (!output_file) {
        fclose(input_file);
        perror("Failed to open output file");
        return -1;
    }

    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE)) {
        fclose(input_file);
        fclose(output_file);
        perror("Failed to generate IV");
        return -1;
    }

    // 写入 IV 到输出文件
    if (fwrite(iv, 1, IV_SIZE, output_file) != IV_SIZE) {
        fclose(input_file);
        fclose(output_file);
        perror("Failed to write IV to output file");
        return -1;
    }


    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(input_file);
        fclose(output_file);
        perror("EVP_CIPHER_CTX_new failed");
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(input_file);
        fclose(output_file);
        perror("EVP_EncryptInit_ex failed");
        return -1;
    }

    unsigned char in_buffer[BUFFER_SIZE];
    int bytes_read;
    while ((bytes_read = fread(in_buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        int out_len;
        unsigned char out_buffer[BUFFER_SIZE + 16];
        if (EVP_EncryptUpdate(ctx, out_buffer, &out_len, in_buffer, bytes_read) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(input_file);
            fclose(output_file);
            perror("EVP_EncryptUpdate failed");
            return -1;
        }
        if (fwrite(out_buffer, 1, out_len, output_file) != out_len) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(input_file);
            fclose(output_file);
            perror("Failed to write encrypted data to output file");
            return -1;
        }
    }

    int final_len;
    unsigned char final_buffer[16];
    if (EVP_EncryptFinal_ex(ctx, final_buffer, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(input_file);
        fclose(output_file);
        perror("EVP_EncryptFinal_ex failed");
        return -1;
    }
    if (fwrite(final_buffer, 1, final_len, output_file) != final_len) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(input_file);
        fclose(output_file);
        perror("Failed to write final block to output file");
        return -1;
    }


    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file);
    fclose(output_file);

    return 0;
}

#define HANDLE_ERROR(msg) do { perror(msg); exit(EXIT_FAILURE); } while (0)

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <password> <input file> <output file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char* password = argv[1];
    const char* input_filename = argv[2];
    const char* output_filename = argv[3];
    unsigned char derived_key[KEY_LENGTH];

    if (derive_key_from_password(password, derived_key, sizeof(derived_key)) != 0) {
        fprintf(stderr, "Key derivation failed\n");
        exit(EXIT_FAILURE);
    }

    if (encrypt_file(input_filename, output_filename, derived_key) != 0) {
        perror("Encryption failed");
        exit(EXIT_FAILURE);
    }

    printf("Encryption successful\n");
    return 0;
}