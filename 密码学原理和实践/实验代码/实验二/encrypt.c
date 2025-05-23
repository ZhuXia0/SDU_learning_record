#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
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
#define HMAC_KEY_LENGTH 32  // HMAC key length

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Generate RSA key pair and save to files
int generate_rsa_keypair(const char* public_key_file, const char* private_key_file) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) handle_errors();

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS) <= 0) handle_errors();

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handle_errors();

    FILE* pub_file = fopen(public_key_file, "wb");
    FILE* priv_file = fopen(private_key_file, "wb");
    if (!pub_file || !priv_file) handle_errors();

    if (!PEM_write_PUBKEY(pub_file, pkey) || !PEM_write_PrivateKey(priv_file, pkey, NULL, NULL, 0, NULL, NULL)) handle_errors();

    fclose(pub_file);
    fclose(priv_file);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0; // Success
}

// Encrypt symmetric key using RSA public key
int rsa_encrypt_key(const char* public_key_file, unsigned char* key, size_t key_len, unsigned char* encrypted_key, size_t* encrypted_key_len) {
    FILE* pub_file = fopen(public_key_file, "rb");
    if (!pub_file) return -1;

    EVP_PKEY* public_key = PEM_read_PUBKEY(pub_file, NULL, NULL, NULL);
    fclose(pub_file);
    if (!public_key) return -1;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) return -1;

    if (EVP_PKEY_encrypt(ctx, NULL, encrypted_key_len, key, key_len) <= 0) return -1;

    if (EVP_PKEY_encrypt(ctx, encrypted_key, encrypted_key_len, key, key_len) <= 0) return -1;

    EVP_PKEY_free(public_key);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

// Encrypt file
int encrypt_file(const char* input_filename, const char* output_filename, unsigned char* key, const char* public_key_file) {
    FILE* input_file = fopen(input_filename, "rb");
    if (!input_file) return -1;

    FILE* output_file = fopen(output_filename, "wb");
    if (!output_file) {
        fclose(input_file);
        return -1;
    }

    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE)) return -1;

    if (fwrite(iv, 1, IV_SIZE, output_file) != IV_SIZE) return -1;

    size_t encrypted_key_len;
    unsigned char encrypted_key[RSA_KEY_BITS / 8];
    if (rsa_encrypt_key(public_key_file, key, KEY_LENGTH, encrypted_key, &encrypted_key_len) != 0) return -1;

    if (fwrite(&encrypted_key_len, sizeof(size_t), 1, output_file) != 1 || fwrite(encrypted_key, 1, encrypted_key_len, output_file) != encrypted_key_len) return -1;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) return -1;

    unsigned char in_buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = fread(in_buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        int out_len;
        unsigned char out_buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
        if (EVP_EncryptUpdate(ctx, out_buffer, &out_len, in_buffer, bytes_read) != 1) return -1;
        if (fwrite(out_buffer, 1, out_len, output_file) != out_len) return -1;
    }

    int final_len;
    unsigned char final_buffer[EVP_MAX_BLOCK_LENGTH];
    if (EVP_EncryptFinal_ex(ctx, final_buffer, &final_len) != 1) return -1;
    if (fwrite(final_buffer, 1, final_len, output_file) != final_len) return -1;

    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file);
    fclose(output_file);

    return 0;
}

int generate_hmac(const char* input_filename, const char* hmac_filename, unsigned char* hmac_key, size_t hmac_key_len) {
    FILE* input_file = fopen(input_filename, "rb");
    if (!input_file) return -1;

    FILE* hmac_file = fopen(hmac_filename, "wb");
    if (!hmac_file) {
        fclose(input_file);
        return -1;
    }

    // Optional: Write HMAC key to a file
    FILE* key_file = fopen("hmac_key.bin", "wb");
    if (key_file) {
        fwrite(hmac_key, 1, hmac_key_len, key_file);
        fclose(key_file);
    }

    unsigned char buffer[BUFFER_SIZE];
    unsigned char hmac_value[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;

    HMAC(EVP_sha256(), hmac_key, hmac_key_len, NULL, 0, hmac_value, &hmac_len); // Initialize HMAC

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        HMAC(EVP_sha256(), hmac_key, hmac_key_len, buffer, bytes_read, hmac_value, &hmac_len);
    }

    fwrite(hmac_value, 1, hmac_len, hmac_file);

    fclose(input_file);
    fclose(hmac_file);

    return 0;
}
// Function to print key in hex
void print_key_hex(unsigned char* key, size_t key_len) {
    for (size_t i = 0; i < key_len; ++i) {
        printf("%02x", key[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <input file> <output file> <public key file> <private key file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char* input_filename = argv[1];
    const char* output_filename = argv[2];
    const char* public_key_file = argv[3];
    const char* private_key_file = argv[4];

    unsigned char key[KEY_LENGTH];
    unsigned char hmac_key[HMAC_KEY_LENGTH];

    if (!RAND_bytes(key, KEY_LENGTH) || !RAND_bytes(hmac_key, HMAC_KEY_LENGTH)) {
        perror("Failed to generate random keys");
        exit(EXIT_FAILURE);
    }

    // Print the symmetric key and HMAC key in hex format
    printf("Symmetric Key: ");
    print_key_hex(key, KEY_LENGTH);
    printf("HMAC Key: ");
    print_key_hex(hmac_key, HMAC_KEY_LENGTH);

    if (encrypt_file(input_filename, output_filename, key, public_key_file) != 0) {
        perror("Encryption failed");
        exit(EXIT_FAILURE);
    }

    // Generate HMAC for the input file
    if (generate_hmac(input_filename, "hmac_data.bin", hmac_key, HMAC_KEY_LENGTH) != 0) {
        perror("HMAC generation failed");
        exit(EXIT_FAILURE);
    }

    printf("Encryption and HMAC generation successful\n");
    return 0;
}