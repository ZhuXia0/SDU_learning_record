#include"padding.h"
int encrypt_cfb(const unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char** ciphertext, int* ciphertext_len) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_cfb());

    // �����ڴ�����ģ��������ܵ���䣬��CFBģʽͨ������Ҫ��䣩
    *ciphertext = (unsigned char*)malloc(plaintext_len + block_size); // ���ط��䣬ʵ�ʿ��ܲ���Ҫ+block_size
    if (*ciphertext == NULL) return 0;

    // ��������ʼ��������
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // ��ʼ�����ܲ���
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv))
        handleErrors();

    // �ṩҪ���ܵ���Ϣ������ü��ܺ�����
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, (unsigned char*)plaintext, plaintext_len))
        handleErrors();
    *ciphertext_len = len;

    // ��ɼ��ܡ���ʱ���ܲ����ж���������ֽڱ�д��
    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) handleErrors(); // ����CFBģʽ����һ��ͨ������ı�len��ֵ����ΪCFB����Ҫ���
    // ������APIҪ�����ǻ��ǵ�������������Ӧ�ü�����
    // ע�⣺����CFB����ģʽ��EVP_EncryptFinal_exͨ�����������������ݣ����*ciphertext_len����Ҫ+=len

    // ����CFBģʽ����Ҫ��䣬���ǿ��Ե������ĳ��ȣ����EVP_EncryptFinal_exû�иı����Ļ���
    // ������ض��������У���������֪��CFB���������䣬���ǿ��Ժ���EVP_EncryptFinal_ex�����len
    // ��Ϊ�˱��ִ����ͨ���Ժͽ�׳�ԣ����ǻ��Ǳ�������һ���ĵ��úͼ��

    // ����
    EVP_CIPHER_CTX_free(ctx);

    // �������Ƿ����˱�ʵ����Ҫ�ĸ�����ڴ棨Ϊ�˰�ȫ����������ǿ������·����ض���
    // ������������У�Ϊ�˼���������ǽ���������Ŀռ�

    return 1;
}

int decrypt_cfb(const unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char** plaintext, int* plaintext_len) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int block_size = EVP_CIPHER_block_size(EVP_aes_256_cfb());

    // �����ڴ������
    *plaintext = (unsigned char*)malloc(ciphertext_len + 1); // +1��Ϊ�˿��ܵĿ���ֹ��
    if (*plaintext == NULL) return 0;

    // ��������ʼ��������
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // ��ʼ�����ܲ���
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv))
        handleErrors();

    // �ṩҪ���ܵ���Ϣ������ý��ܺ�����
    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    *plaintext_len = len;

    // ��ɽ��ܡ���ʱ���ܲ����ж���������ֽڱ�д�루����CFBģʽ��˵��������ȷ�ģ�
    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) {
        // ����CFB����ģʽ����һ��ͨ������ı�len��ֵ��Ҳ����������������
        // ���������ĳ��ԭ��ʧ���ˣ������ϲ�Ӧ�ã���������Ҫ�������
        handleErrors();
    }
    // ע�⣺ͬ���أ�����CFBģʽ����Ҫ��䣬���ǲ���Ҫ��ΪEVP_DecryptFinal_ex������*plaintext_len

    // �������Ƿ����˱�ʵ����Ҫ�ĸ�����ڴ棨Ϊ�˰�ȫ����������ǵ����ܵĿ���ֹ���������ǽض���
    // ������������У�Ϊ�˼������������Ϊ����֪��CFB���������䣬����ֻ��Ҫȷ�����ǿ���ֹ��
    (*plaintext)[*plaintext_len] = '\0'; // ����ֹ���ܺ���ı����������뽫����Ϊ�ַ�������ʱ����Ҫ��

    // ����
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}
