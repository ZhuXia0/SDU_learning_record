#include"padding.h"
int encrypt_cfb(const unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char** ciphertext, int* ciphertext_len) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_cfb());

    // 分配内存给密文（包括可能的填充，但CFB模式通常不需要填充）
    *ciphertext = (unsigned char*)malloc(plaintext_len + block_size); // 保守分配，实际可能不需要+block_size
    if (*ciphertext == NULL) return 0;

    // 创建并初始化上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // 初始化加密操作
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv))
        handleErrors();

    // 提供要加密的消息，并获得加密后的输出
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, (unsigned char*)plaintext, plaintext_len))
        handleErrors();
    *ciphertext_len = len;

    // 完成加密。此时可能不会有额外的密文字节被写入
    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) handleErrors(); // 对于CFB模式，这一步通常不会改变len的值，因为CFB不需要填充
    // 但由于API要求，我们还是调用了它，并且应该检查错误
    // 注意：对于CFB等流模式，EVP_EncryptFinal_ex通常不会输出额外的数据，因此*ciphertext_len不需要+=len

    // 由于CFB模式不需要填充，我们可以调整密文长度（如果EVP_EncryptFinal_ex没有改变它的话）
    // 在这个特定的例子中，由于我们知道CFB不会添加填充，我们可以忽略EVP_EncryptFinal_ex的输出len
    // 但为了保持代码的通用性和健壮性，我们还是保留了这一步的调用和检查

    // 清理
    EVP_CIPHER_CTX_free(ctx);

    // 由于我们分配了比实际需要的更多的内存（为了安全起见），我们可以重新分配或截断它
    // 但在这个例子中，为了简单起见，我们将保留额外的空间

    return 1;
}

int decrypt_cfb(const unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char** plaintext, int* plaintext_len) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_cfb());

    // 分配内存给明文
    *plaintext = (unsigned char*)malloc(ciphertext_len + 1); // +1是为了可能的空终止符
    if (*plaintext == NULL) return 0;

    // 创建并初始化上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // 初始化解密操作
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv))
        handleErrors();

    // 提供要解密的消息，并获得解密后的输出
    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    *plaintext_len = len;

    // 完成解密。此时可能不会有额外的明文字节被写入（对于CFB模式来说，这是正确的）
    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) {
        // 对于CFB等流模式，这一步通常不会改变len的值，也不会输出额外的数据
        // 但如果由于某种原因失败了（理论上不应该），我们需要处理错误
        handleErrors();
    }
    // 注意：同样地，由于CFB模式不需要填充，我们不需要因为EVP_DecryptFinal_ex而调整*plaintext_len

    // 由于我们分配了比实际需要的更多的内存（为了安全起见，并考虑到可能的空终止符），我们截断它
    // 但在这个例子中，为了简单起见，并且因为我们知道CFB不会添加填充，我们只需要确保它是空终止的
    (*plaintext)[*plaintext_len] = '\0'; // 空终止解密后的文本（仅当你想将其作为字符串处理时才需要）

    // 清理
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}
