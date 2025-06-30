#define _CRT_SECURE_NO_WARNINGS
#pragma once
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <openssl/applink.c>  
#endif
#define MAX_DEPTH 64  // ��ֹ�����ļ�����ջ���
#define RSA_KEY_BITS 2048

void handle_errors() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}


// ����RSA˽Կ�����浽�ļ�
int generate_rsa_private_key(const char* private_key_file) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) handle_errors();

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS) <= 0) handle_errors();

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handle_errors();

    FILE* priv_file = fopen(private_key_file, "wb");
    if (!priv_file) {
        perror("Failed to open private key file");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    int success = PEM_write_PrivateKey(priv_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(priv_file);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return success;
}

// ��˽Կ�ļ���ȡ��Կ������
int extract_public_key(const char* private_key_file, const char* public_key_file) {
    FILE* priv_file = fopen(private_key_file, "rb");
    if (!priv_file) {
        perror("Failed to open private key file");
        return 0;
    }

    EVP_PKEY* private_key = PEM_read_PrivateKey(priv_file, NULL, NULL, NULL);
    fclose(priv_file);
    if (!private_key) {
        fprintf(stderr, "Failed to read private key\n");
        return 0;
    }

    EVP_PKEY* public_key = EVP_PKEY_dup(private_key);
    EVP_PKEY_free(private_key);
    if (!public_key) {
        fprintf(stderr, "Failed to extract public key\n");
        return 0;
    }

    FILE* pub_file = fopen(public_key_file, "wb");
    if (!pub_file) {
        perror("Failed to open public key file");
        EVP_PKEY_free(public_key);
        return 0;
    }

    int success = PEM_write_PUBKEY(pub_file, public_key);
    fclose(pub_file);
    EVP_PKEY_free(public_key);

    return success;
}
// ����֤������(CSR)
int generate_certificate_request(const char* private_key_file, const char* csr_file) {
    // ��ȡ˽Կ
    FILE* priv_file = fopen(private_key_file, "rb");
    if (!priv_file) {
        perror("Failed to open private key file");
        return 0;
    }
    //pkey��openssl�е�һ�� EVP_PKEY �������ͬʱ�洢��˽Կ�ԡ�
    //��ʹ�Ҵ�˽Կ�ļ����� private.key�����أ�OpenSSL Ҳ���Զ��������洢���еĹ�Կ����
    EVP_PKEY* private_key = PEM_read_PrivateKey(priv_file, NULL, NULL, NULL);
    fclose(priv_file);
    if (!private_key) {
        fprintf(stderr, "Failed to read private key\n");
        return 0;
    }

    // ����֤������
    X509_REQ* req = X509_REQ_new();
    if (!req) {
        fprintf(stderr, "Failed to create certificate request\n");
        EVP_PKEY_free(private_key);
        return 0;
    }

    // ���ð汾
    X509_REQ_set_version(req, X509_REQ_VERSION_1);

    // ���ù�Կ
    if (!X509_REQ_set_pubkey(req, private_key)) {
        fprintf(stderr, "Failed to set public key in request\n");
        X509_REQ_free(req);
        EVP_PKEY_free(private_key);
        return 0;
    }

    // ����Subject����
    X509_NAME* name = X509_NAME_new();
    if (!name) {
        fprintf(stderr, "Failed to create X509 name\n");
        X509_REQ_free(req);
        EVP_PKEY_free(private_key);
        return 0;
    }

    // ����ʽ����Subject��Ϣ
    char input[256];

    printf("You are about to be asked to enter information that will be incorporated\n");
    printf("into your certificate request. What you are about to enter is what is called\n");
    printf("a Distinguished Name or a DN. There are quite a few fields but you can leave\n");
    printf("some blank. For some fields there will be a default value. If you enter '.',\n");
    printf("the field will be left blank.\n\n");

    printf("Country Name (2 letter code) [AU]: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    printf("State or Province Name (full name) [Some-State]: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    printf("Locality Name (eg, city) []: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    printf("Organization Name (eg, company) [Internet Widgets Pty Ltd]: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    printf("Organizational Unit Name (eg, section) []: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    printf("Common Name (e.g. server FQDN or YOUR name) []: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    printf("Email Address []: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    // ����Subject������
    X509_REQ_set_subject_name(req, name);
    X509_NAME_free(name);

    // ǩ������
    if (!X509_REQ_sign(req, private_key, EVP_sha256())) {
        fprintf(stderr, "Failed to sign certificate request\n");
        X509_REQ_free(req);
        EVP_PKEY_free(private_key);
        return 0;
    }

    // д��CSR�ļ�
    FILE* csr_file_ptr = fopen(csr_file, "wb");
    if (!csr_file_ptr) {
        perror("Failed to open CSR file");
        X509_REQ_free(req);
        EVP_PKEY_free(private_key);
        return 0;
    }

    int success = PEM_write_X509_REQ(csr_file_ptr, req);
    fclose(csr_file_ptr);
    X509_REQ_free(req);
    EVP_PKEY_free(private_key);

    return success;
}

// ����ʽ��ȡ�û�����
void read_input(const char* prompt, char* buffer, size_t max_len) {
    printf("%s", prompt);
    if (fgets(buffer, max_len, stdin)) {
        buffer[strcspn(buffer, "\n")] = '\0';
    }
}

// ������ǩ��֤��
int generate_self_signed_cert(const char* key_file, const char* cert_file, int days) {
    // 1. ��ȡ����˽Կ
    FILE* key_fp = fopen(key_file, "rb");
    if (!key_fp) {
        perror("Error opening private key file");
        return 0;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(key_fp, NULL, NULL, NULL);
    fclose(key_fp);
    if (!pkey) {
        fprintf(stderr, "Error reading private key\n");
        return 0;
    }

    // 2. ����X509֤��ṹ
    X509* x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        return 0;
    }

    // 3. ����֤��汾
    X509_set_version(x509, X509_VERSION_3);

    // 4. ����������к�
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // 5. ������Ч��
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), days * 24 * 3600);

    // 6. ���ù�Կ����˽Կ��ȡ��
    X509_set_pubkey(x509, pkey);

    // 7. ����ʽ����Subject��Ϣ
    X509_NAME* name = X509_get_subject_name(x509);

    printf("\nYou are about to be asked to enter information that will be incorporated\n");
    printf("into your certificate request. What you are about to enter is what is called\n");
    printf("a Distinguished Name or a DN. There are quite a few fields but you can leave\n");
    printf("some blank. For some fields there will be a default value. If you enter '.',\n");
    printf("the field will be left blank.\n\n");

    char input[256];

    read_input("Country Name (2 letter code) [AU]: ", input, sizeof(input));
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    read_input("State or Province Name (full name) [Some-State]: ", input, sizeof(input));
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    read_input("Locality Name (eg, city) []: ", input, sizeof(input));
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    read_input("Organization Name (eg, company) [Internet Widgets Pty Ltd]: ", input, sizeof(input));
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    read_input("Organizational Unit Name (eg, section) []: ", input, sizeof(input));
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    read_input("Common Name (e.g. server FQDN or YOUR name) []: ", input, sizeof(input));
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    read_input("Email Address []: ", input, sizeof(input));
    if (strlen(input) > 0) {
        X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_ASC, (unsigned char*)input, -1, -1, 0);
    }

    // 8. ���ð䷢����Ϣ����ǩ��֤����Subject��ͬ��
    X509_set_issuer_name(x509, name);

    // 9. ��˽Կǩ��֤��
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        fprintf(stderr, "Error signing certificate\n");
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return 0;
    }

    // 10. ����֤��
    FILE* cert_fp = fopen(cert_file, "wb");
    if (!cert_fp) {
        perror("Error opening certificate file");
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return 0;
    }
    PEM_write_X509(cert_fp, x509);
    fclose(cert_fp);

    // 11. �ͷ���Դ
    X509_free(x509);
    EVP_PKEY_free(pkey);

    return 1;
}

// ���� PKCS12 �ļ�
int generate_pkcs12(const char* key_file, const char* cert_file,
    const char* ca_file, const char* output_file,
    const char* friendly_name, const char* password) {
    // 1. ��ȡ˽Կ
    FILE* key_fp = fopen(key_file, "rb");
    if (!key_fp) {
        perror("Error opening private key file");
        return 0;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(key_fp, NULL, NULL, NULL);
    fclose(key_fp);
    if (!pkey) {
        fprintf(stderr, "Error reading private key\n");
        return 0;
    }

    // 2. ��ȡ֤��
    FILE* cert_fp = fopen(cert_file, "rb");
    if (!cert_fp) {
        perror("Error opening certificate file");
        EVP_PKEY_free(pkey);
        return 0;
    }
    X509* cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    fclose(cert_fp);
    if (!cert) {
        fprintf(stderr, "Error reading certificate\n");
        EVP_PKEY_free(pkey);
        return 0;
    }

    // 3. ��ȡCA֤��������ѡ��
    STACK_OF(X509)* ca_stack = NULL;
    if (ca_file && strlen(ca_file) > 0) {
        FILE* ca_fp = fopen(ca_file, "rb");
        if (!ca_fp) {
            perror("Error opening CA certificate file");
            X509_free(cert);
            EVP_PKEY_free(pkey);
            return 0;
        }
        ca_stack = sk_X509_new_null();
        X509* ca_cert;
        while ((ca_cert = PEM_read_X509(ca_fp, NULL, NULL, NULL))) {
            sk_X509_push(ca_stack, ca_cert);
        }
        fclose(ca_fp);
    }

    // 4. ����PKCS12�ṹ
    PKCS12* p12 = PKCS12_create(password, friendly_name, pkey, cert, ca_stack,
        NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
        NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
        PKCS12_DEFAULT_ITER, PKCS12_DEFAULT_ITER, 0);
    if (!p12) {
        fprintf(stderr, "Error creating PKCS12 structure\n");
        if (ca_stack) sk_X509_pop_free(ca_stack, X509_free);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return 0;
    }

    // 5. д���ļ�
    FILE* out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        perror("Error opening output file");
        PKCS12_free(p12);
        if (ca_stack) sk_X509_pop_free(ca_stack, X509_free);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return 0;
    }
    int ret = i2d_PKCS12_fp(out_fp, p12);
    fclose(out_fp);

    // 6. ������Դ
    PKCS12_free(p12);
    if (ca_stack) sk_X509_pop_free(ca_stack, X509_free);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    return ret;
}
// PKCS12�������
int extract_pkcs12(const char* p12_file, const char* password,
    const char* key_out, const char* cert_out) {
    FILE* fp = fopen(p12_file, "rb");
    if (!fp) {
        perror("Error opening PKCS12 file");
        return 0;
    }

    PKCS12* p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (!p12) {
        fprintf(stderr, "Error reading PKCS12 structure\n");
        return 0;
    }

    // ��֤MAC�������飩
    if (!PKCS12_verify_mac(p12, password, -1)) {
        fprintf(stderr, "Password verification failed\n");
        PKCS12_free(p12);
        return 0;
    }

    EVP_PKEY* pkey = NULL;
    X509* cert = NULL;
    STACK_OF(X509)* ca_stack = NULL;

    if (!PKCS12_parse(p12, password, &pkey, &cert, &ca_stack)) {
        fprintf(stderr, "Failed to parse PKCS12 (wrong password?)\n");
        PKCS12_free(p12);
        return 0;
    }

    // ��֤��Կ��ƥ��
    if (cert && !X509_check_private_key(cert, pkey)) {
        fprintf(stderr, "Certificate does not match private key\n");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        sk_X509_pop_free(ca_stack, X509_free);
        PKCS12_free(p12);
        return 0;
    }

    // ���˽Կ
    int success = 1;
    if (key_out) {
        FILE* key_fp = fopen(key_out, "wb");
        if (!key_fp) {
            perror("Error opening key output file");
            success = 0;
        }
        else {
            success = PEM_write_PrivateKey(key_fp, pkey, NULL, NULL, 0, NULL, NULL);
            fclose(key_fp);
            if (!success) fprintf(stderr, "Failed to write private key\n");
        }
    }

    // ���֤�飨��ѡ��
    if (success && cert_out && cert) {
        FILE* cert_fp = fopen(cert_out, "wb");
        if (!cert_fp) {
            perror("Error opening cert output file");
            success = 0;
        }
        else {
            success = PEM_write_X509(cert_fp, cert);
            fclose(cert_fp);
            if (!success) fprintf(stderr, "Failed to write certificate\n");
        }
    }

    // ������Դ
    EVP_PKEY_free(pkey);
    X509_free(cert);
    sk_X509_pop_free(ca_stack, X509_free);
    PKCS12_free(p12);

    return success;
}

// ASN.1 ����������
static const struct {
    int tag;
    const char* name;
} asn1_tags[] = {
    {V_ASN1_BOOLEAN, "BOOLEAN"},
    {V_ASN1_INTEGER, "INTEGER"},
    {V_ASN1_BIT_STRING, "BIT STRING"},
    {V_ASN1_OCTET_STRING, "OCTET STRING"},
    {V_ASN1_NULL, "NULL"},
    {V_ASN1_OBJECT, "OBJECT"},
    {V_ASN1_UTF8STRING, "UTF8STRING"},
    {V_ASN1_SEQUENCE, "SEQUENCE"},
    {V_ASN1_SET, "SET"},
    {V_ASN1_PRINTABLESTRING, "PRINTABLESTRING"},
    {V_ASN1_IA5STRING, "IA5STRING"},
    {V_ASN1_UTCTIME, "UTCTIME"},
    {V_ASN1_GENERALIZEDTIME, "GENERALIZEDTIME"},
    {V_ASN1_T61STRING, "T61STRING"},
    {V_ASN1_IA5STRING, "IA5STRING"},
    {V_ASN1_UNIVERSALSTRING, "UNIVERSALSTRING"},
    {V_ASN1_BMPSTRING, "BMPSTRING"},
    {V_ASN1_VISIBLESTRING, "VISIBLESTRING"},
    {V_ASN1_ENUMERATED, "ENUMERATED"},
    {V_ASN1_ENUMERATED,    "ENUMERATED"},
    {V_ASN1_VISIBLESTRING, "VISIBLESTRING"},
    {V_ASN1_T61STRING,     "T61STRING"},
    {V_ASN1_BMPSTRING,     "BMPSTRING"},
    {V_ASN1_UNIVERSALSTRING,"UNIVERSALSTRING"},
    {V_ASN1_NUMERICSTRING, "NUMERICSTRING"},
    {V_ASN1_VIDEOTEXSTRING,"VIDEOTEXSTRING"},
    {V_ASN1_GRAPHICSTRING, "GRAPHICSTRING"},
    {V_ASN1_ISO64STRING,   "ISO64STRING"},
    {V_ASN1_GENERALSTRING, "GENERALSTRING"},
    {V_ASN1_TELETEXSTRING, "TELETEXSTRING"},
    {0, NULL}
};

const char* get_asn1_type_name(int tag) {
    for (int i = 0; asn1_tags[i].name; i++) {
        if (asn1_tags[i].tag == tag) {
            return asn1_tags[i].name;
        }
    }
    return "UNKNOWN";
}

void print_indent(const unsigned char* p, const unsigned char* start, int depth, FILE* out) {
    fprintf(out, "%4ld:d=%d ", (long)(p - start), depth);
    for (int i = 0; i < depth; i++) {
        fprintf(out, "  ");
    }
}
// �ݹ����ASN.1�ṹ
void parse_asn1(const unsigned char** data, long length, int depth, FILE* out) {
    const unsigned char* p = *data;
    const unsigned char* start = p;
    const unsigned char* end = p + length;

    while (p < end && depth < MAX_DEPTH) {
        const unsigned char* elem_start = p;  // ��¼Ԫ����ʼλ��
        int tag, klass;
        long tag_len;
        int is_constructed = 0;

        // 1. ����TLVͷ��
        int ret = ASN1_get_object(&p, &tag_len, &tag, &klass, end - p);
        is_constructed = ret & V_ASN1_CONSTRUCTED;
        long header_len = p - elem_start;
        const unsigned char* value_ptr = p;  // Value���ֿ�ʼλ��

        // 2. ��ǿ�Ĵ�����
        if (ret & 0x80) {
            fprintf(out, "%4ld:d=%d [ERROR] Invalid ASN.1 header\n",
                (long)(elem_start - start), depth);
            break;
        }
        if (p + tag_len > end) {
            fprintf(out, "%4ld:d=%d [ERROR] Length overflow (hl=%ld l=%ld remain=%ld)\n",
                (long)(elem_start - start), depth,
                header_len, tag_len, (long)(end - p));
            break;
        }

        // 3. ��ӡԪ����Ϣ
        fprintf(out, "%4ld:d=%d hl=%ld l=%4ld ",
            (long)(elem_start - start), depth, header_len, tag_len);

        // 4. ����������
        if (is_constructed) {
            fprintf(out, "cons: %s\n", get_asn1_type_name(tag));

            const unsigned char* temp_ptr = p;
            parse_asn1(&temp_ptr, tag_len, depth + 1, out);
            p = temp_ptr;  // �ؼ��㣺�������ָ��λ��
        }
        // 5. �����������
        else {
            fprintf(out, "prim: %s", get_asn1_type_name(tag));

            // ��������ֵ����
            switch (tag) {
            case V_ASN1_INTEGER: {
                // ����ʾ��ʵ��ʹ��ASN1_INTEGER�������ȫ
                fprintf(out, ":");
                for (long i = 0; i < tag_len && i < 8; i++) {
                    fprintf(out, "%02X", value_ptr[i]);
                }
                if (tag_len > 8) fprintf(out, "...");
                break;
            }
            case V_ASN1_UTCTIME:
            case V_ASN1_GENERALIZEDTIME: {
                // ����ʾʱ������
                fprintf(out, ":%.*s", (int)tag_len, value_ptr);
                break;
            }
            case V_ASN1_OBJECT: {
                char objbuf[256];
                OBJ_obj2txt(objbuf, sizeof(objbuf), (ASN1_OBJECT*)value_ptr, 1);
                fprintf(out, ":%s", objbuf);
                break;
            }
            case V_ASN1_BOOLEAN:
                fprintf(out, ":%s", *value_ptr ? "TRUE" : "FALSE");
                break;
            case V_ASN1_PRINTABLESTRING:
            case V_ASN1_IA5STRING:
            case V_ASN1_UTF8STRING:
                // ��ӳ��ȼ���ֹԽ��
                if (tag_len > 0 && value_ptr[tag_len - 1] == '\0') {
                    fprintf(out, ":%s", value_ptr);
                }
                else {
                    fprintf(out, ":%.*s", (int)tag_len, value_ptr);
                }
                break;
             // ����case���...
            case V_ASN1_ENUMERATED: {
                fprintf(out, ":");
                for (long i = 0; i < tag_len && i < 8; i++) {
                    fprintf(out, "%02X", value_ptr[i]);
                }
                if (tag_len > 8) fprintf(out, "...");
                break;
            }

            case V_ASN1_VISIBLESTRING:
            case V_ASN1_T61STRING:
            case V_ASN1_BMPSTRING:
            case V_ASN1_UNIVERSALSTRING:
            case V_ASN1_NUMERICSTRING:
                fprintf(out, ":%.*s", (int)tag_len, value_ptr);
                break;

            case V_ASN1_VIDEOTEXSTRING:
            case V_ASN1_GRAPHICSTRING:
                fprintf(out, "[VIDEO/GRAPHIC DATA]");
                break;
            default:
                // ������ȫδ֪�����ͣ�������ʾHEXֵ
                fprintf(out, "[UNKNOWN-TAG-%d]:", tag);
                for (long i = 0; i < (tag_len > 8 ? 8 : tag_len); i++) {
                    fprintf(out, "%02X", value_ptr[i]);
                }
                if (tag_len > 8) fprintf(out, "...");

            }
            fprintf(out, "\n");
            p += tag_len;  // �ƶ�ָ�뵽��һ��Ԫ��
        }
    }
    *data = p;  // �����ⲿָ��
}

// BIOתDER��������
long bio_to_der(BIO* bio, unsigned char** der) {
    unsigned char buf[4096];
    long total = 0;
    int len;

    *der = NULL;
    BIO* mem = BIO_new(BIO_s_mem());
    if (!mem) return -1;

    while ((len = BIO_read(bio, buf, sizeof(buf))) > 0) {
        BIO_write(mem, buf, len);
        total += len;
    }

    *der = (unsigned char*)OPENSSL_malloc(total);
    if (!*der) {
        BIO_free(mem);
        return -1;
    }

    BIO_read(mem, *der, total);
    BIO_free(mem);
    return total;
}

// ����������
int parse_asn1_file(const char* filename, FILE* out) {
    BIO* bio = NULL;
    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;
    unsigned char* der_data = NULL;
    long der_len = 0;
    int ret = 0;

    // 1. ���Զ�ȡ PEM ��ʽ�ļ�
    bio = BIO_new_file(filename, "r");
    if (!bio) {
        fprintf(stderr, "Error opening file: %s\n", filename);
        if (der_data) OPENSSL_free(der_data);
        if (bio) BIO_free(bio);
        if (cert) X509_free(cert);
        if (pkey) EVP_PKEY_free(pkey);
        return ret;
    }

    // 2. ���Խ���Ϊ���� PEM ��ʽ
    if (strstr(filename, ".pem") || strstr(filename, ".key") || strstr(filename, ".crt") || strstr(filename, ".csr")||strstr(filename, ".p12") || strstr(filename, ".pfx")) {
        // ������Ϊ֤�����
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (cert) {
            fprintf(out, "=== X509 Certificate Structure ===\n");
            der_len = i2d_X509(cert, &der_data);
            if (der_data && der_len > 0) {
                const unsigned char* p = der_data;
                parse_asn1(&p, der_len, 0, out);
                ret = 1;
            }
        }
        BIO_seek(bio, 0);

        // ������Ϊ˽Կ����
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (pkey) {
            fprintf(out, "=== Private Key Structure ===\n");
            der_len = i2d_PrivateKey(pkey, &der_data);
            if (der_data && der_len > 0) {
                const unsigned char* p = der_data;
                parse_asn1(&p, der_len, 0, out);
                ret = 1;
            }
        }
        BIO_seek(bio, 0);

        // ������ΪCSR����
        X509_REQ* req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
        if (req) {
            fprintf(out, "=== Certificate Request (CSR) Structure ===\n");
            der_len = i2d_X509_REQ(req, &der_data);
            X509_REQ_free(req);
            if (der_data && der_len > 0) {
                const unsigned char* p = der_data;
                parse_asn1(&p, der_len, 0, out);
                ret = 1;
            }
        }
        BIO_seek(bio, 0);
    
    }
    
    // 3. ����ֱ�Ӷ�ȡ DER ��ʽ����������������ʽ��ֱ�ӱ�������
    else {
        BIO_free(bio);
        bio = BIO_new_file(filename, "rb");
        if (!bio) {
            fprintf(stderr, "Error reopening file in binary mode\n");
            if (der_data) OPENSSL_free(der_data);
            if (bio) BIO_free(bio);
            if (cert) X509_free(cert);
            if (pkey) EVP_PKEY_free(pkey);
            return ret;
        }

        der_len = bio_to_der(bio, &der_data);
        if (der_len <= 0) {
            fprintf(stderr, "Unrecognized file format or parsing error\n");
            if (der_data) OPENSSL_free(der_data);
            if (bio) BIO_free(bio);
            if (cert) X509_free(cert);
            if (pkey) EVP_PKEY_free(pkey);
            return ret;
        }

        fprintf(out, "=== Raw ASN.1 Structure ===\n");


        if (der_data && der_len > 0) {
            const unsigned char* p = der_data;
            parse_asn1(&p, der_len, 0, out);
            ret = 1;
        }

    }
    if (der_data) OPENSSL_free(der_data);
    if (bio) BIO_free(bio);
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);
    return ret;
}



void print_usage(const char* program_name) {
    fprintf(stderr, "Usage And Examples:\n");
    fprintf(stderr, "   RSAUsage:\n");
    fprintf(stderr, "  Generate private key: %s -out <private_key_file>\n", program_name);
    fprintf(stderr, "  Extract public key: %s -in <private_key_file> -out <public_key_file>\n", program_name);
    fprintf(stderr, "   \n");
    fprintf(stderr, "   CertUsage:\n");
    fprintf(stderr, "  Generate certificate request: %s req -new -key <private_key_file> -out <csr_file>\n", program_name);
    fprintf(stderr, "  Generate self-signed cert: %s req -x509 -key <keyfile> -out <certfile> -days <days>\n", program_name);
    fprintf(stderr, "   Examples:\n");
    fprintf(stderr, "  %s req -x509 -key server.key -out server.crt -days 365\n", program_name);
    fprintf(stderr, "   \n");
    fprintf(stderr, "   PKCS12_Usage:\n");
    fprintf(stderr, "  Generate PKCS12: %s pkcs12 -inkey <keyfile> -in <certfile> [-certfile <cafile>] -out <output> [-name \"name\"] -password pass:<password>\n", program_name);
    fprintf(stderr, "  Extract PKCS12:  %s extract -in <p12file> -outkey <keyout> [-outcert <certout>] -password pass:<password>\n", program_name);
    fprintf(stderr, "   Examples:\n");
    fprintf(stderr, "  %s pkcs12 -inkey server.key -in server.crt -out bundle.p12 -password pass:123456\n", program_name);
    fprintf(stderr, "  %s extract -in bundle.p12 -outkey extracted.key -outcert extracted.crt -password pass:123456\n", program_name);
    fprintf(stderr, "   \n");
    fprintf(stderr, "   Parse ASN1_Usage:\n");
    fprintf(stderr, "  Parse ASN1:  %s parse -in <file> [-der]\n", program_name);
}

int main(int argc, char* argv[]) {
    if (argc == 3 && strcmp(argv[1], "-out") == 0) {
        // ����˽Կģʽ
        if (!generate_rsa_private_key(argv[2])) {
            fprintf(stderr, "Failed to generate private key\n");
            return EXIT_FAILURE;
        }
        printf("Successfully generated RSA private key: %s\n", argv[2]);
    }
    else if (argc == 5 && strcmp(argv[1], "-in") == 0 && strcmp(argv[3], "-out") == 0) {
        // ��ȡ��Կģʽ
        if (!extract_public_key(argv[2], argv[4])) {
            fprintf(stderr, "Failed to extract public key\n");
            return EXIT_FAILURE;
        }
        printf("Successfully extracted public key: %s (from %s)\n", argv[4], argv[2]);
    }
    else if (argc == 7 && strcmp(argv[1], "req") == 0 && strcmp(argv[2], "-new") == 0 &&
        strcmp(argv[3], "-key") == 0 && strcmp(argv[5], "-out") == 0) {
        // ����֤������ģʽ
        if (!generate_certificate_request(argv[4], argv[6])) {
            fprintf(stderr, "Failed to generate certificate request\n");
            return EXIT_FAILURE;
        }
        printf("Successfully generated certificate request: %s (using key %s)\n", argv[6], argv[4]);
    }
    else if (argc == 9 &&
        strcmp(argv[1], "req") == 0 &&
        strcmp(argv[2], "-x509") == 0 &&
        strcmp(argv[3], "-key") == 0 &&
        strcmp(argv[5], "-out") == 0 &&
        strcmp(argv[7], "-days") == 0) {

        int days = atoi(argv[8]);
        if (days <= 0) {
            fprintf(stderr, "Invalid days value\n");
            return EXIT_FAILURE;
        }

        if (!generate_self_signed_cert(argv[4], argv[6], days)) {
            fprintf(stderr, "Failed to generate self-signed certificate\n");
            return EXIT_FAILURE;
        }

        printf("Successfully generated:\n");
        printf("  Using private key: %s\n", argv[4]);
        printf("  Certificate: %s (valid for %d days)\n", argv[6], days);
    }
    else if (argc >= 10 && strcmp(argv[1], "pkcs12") == 0) {
        // ��������
        const char* key_file = NULL;
        const char* cert_file = NULL;
        const char* ca_file = NULL;
        const char* output_file = NULL;
        const char* friendly_name = "My Certificate";
        const char* password = NULL;
        //��Ϊ�����࣬�������Ժ��Զ������֮���˳������
        for (int i = 2; i < argc; ) {
            if (strcmp(argv[i], "-inkey") == 0 && i + 1 < argc) {
                key_file = argv[i + 1];
                i += 2;
            }
            else if (strcmp(argv[i], "-in") == 0 && i + 1 < argc) {
                cert_file = argv[i + 1];
                i += 2;
            }
            else if (strcmp(argv[i], "-certfile") == 0 && i + 1 < argc) {
                ca_file = argv[i + 1];
                i += 2;
            }
            else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
                output_file = argv[i + 1];
                i += 2;
            }
            else if (strcmp(argv[i], "-name") == 0 && i + 1 < argc) {
                friendly_name = argv[i + 1];
                i += 2;
            }
            else if (strcmp(argv[i], "-password") == 0 && i + 1 < argc) {
                if (strncmp(argv[i + 1], "pass:", 5) == 0) {
                    password = argv[i + 1] + 5;
                }
                i += 2;
            }
            else {
                i++;
            }
        }

        // ����Ҫ����
        if (!key_file || !cert_file || !output_file || !password) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }

        // ����PKCS12�ļ�
        if (!generate_pkcs12(key_file, cert_file, ca_file, output_file,
            friendly_name, password)) {
            fprintf(stderr, "Failed to generate PKCS12 file\n");
            return EXIT_FAILURE;
        }
        

        printf("Successfully generated PKCS12 file: %s\n", output_file);
    }
    else if (argc >= 8 && strcmp(argv[1], "extract") == 0) {
        // PKCS12���ģʽ
        const char* p12_file = NULL;
        const char* key_out = NULL;
        const char* cert_out = NULL;
        const char* password = NULL;
        //ѭ���������������������˲���˳���Ҫ��ֻ�в������ڼ���
        for (int i = 2; i < argc; ) {
            if (strcmp(argv[i], "-in") == 0 && i + 1 < argc) {
                p12_file = argv[i + 1];
                i += 2;
            }
            else if (strcmp(argv[i], "-outkey") == 0 && i + 1 < argc) {
                key_out = argv[i + 1];
                i += 2;
            }
            else if (strcmp(argv[i], "-outcert") == 0 && i + 1 < argc) {
                cert_out = argv[i + 1];
                i += 2;
            }
            else if (strcmp(argv[i], "-password") == 0 && i + 1 < argc) {
                if (strncmp(argv[i + 1], "pass:", 5) == 0) {
                    password = argv[i + 1] + 5;
                }
                i += 2;
            }
            else {
                i++;
            }
        }

        // ����Ҫ����
        if (!p12_file || !key_out || !password) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }

        if (!extract_pkcs12(p12_file, password, key_out, cert_out)) {
            fprintf(stderr, "Failed to extract PKCS12 file\n");
            return EXIT_FAILURE;
        }

        printf("Successfully extracted:\n");
        printf("  Private key: %s\n", key_out);
        if (cert_out) printf("  Certificate: %s\n", cert_out);
        }
    else if (argc == 4 && strcmp(argv[1], "parse") == 0 && strcmp(argv[2], "-in") == 0) {
        if (!parse_asn1_file(argv[3], stdout)) {
            fprintf(stderr, "Failed to parse ASN1 file\n");
            return EXIT_FAILURE;
        }
        printf("Successfully parsed ASN1 file: %s\n", argv[3]);
    }

    else {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}