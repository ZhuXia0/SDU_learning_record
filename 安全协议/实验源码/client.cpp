#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/provider.h>
#include <openssl/applink.c>  
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define SERVER_IP L"127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024

void init_openssl() {
    printf("\n[OpenSSL Initialization Phase]\n");
    printf("Using OpenSSL 3.0+ initialization style\n");
    // OpenSSL 3.0+ 不再需要显式调用 SSL_load_error_strings() 和 OpenSSL_add_ssl_algorithms()
}

void cleanup_openssl() {
    printf("\n[OpenSSL Cleanup Phase]\n");
    printf("Unloading OpenSSL providers...\n");
    OSSL_PROVIDER_unload(OSSL_PROVIDER_try_load(NULL, "default", 1));
    printf("Cleaning up OpenSSL resources...\n");
    EVP_cleanup();
    printf("OpenSSL cleanup completed.\n");
}

void print_certificate_info(X509* cert) {
    printf("\n[Certificate Verification Phase]\n");
    printf("Printing server certificate details...\n");

    BIO* bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!bio) {
        fprintf(stderr, "Error creating BIO\n");
        return;
    }

    printf("\n=== Server Certificate Details ===\n");

    // 打印主题信息
    printf("Subject: ");
    X509_NAME_print_ex(bio, X509_get_subject_name(cert), 0, XN_FLAG_ONELINE);
    printf("\n");

    // 打印颁发者信息
    printf("Issuer: ");
    X509_NAME_print_ex(bio, X509_get_issuer_name(cert), 0, XN_FLAG_ONELINE);
    printf("\n");

    // 打印有效期
    printf("Validity: ");
    ASN1_TIME_print(bio, X509_get0_notBefore(cert));
    printf(" - ");
    ASN1_TIME_print(bio, X509_get0_notAfter(cert));
    printf("\n");

    // 打印序列号
    printf("Serial Number: ");
    i2a_ASN1_INTEGER(bio, X509_get0_serialNumber(cert));
    printf("\n");

    // 打印签名算法
    printf("Signature Algorithm: ");
    i2a_ASN1_OBJECT(bio, X509_get0_tbs_sigalg(cert)->algorithm);
    printf("\n");

    // 打印公钥信息
    EVP_PKEY* pkey = X509_get0_pubkey(cert);
    if (pkey) {
        printf("Public Key: ");
        EVP_PKEY_print_public(bio, pkey, 0, NULL);
    }

    // 打印扩展信息
    printf("\nExtensions:\n");
    int ext_count = X509_get_ext_count(cert);
    for (int i = 0; i < ext_count; i++) {
        X509_EXTENSION* ext = X509_get_ext(cert, i);
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
        BIO_printf(bio, "  ");
        i2a_ASN1_OBJECT(bio, obj);
        printf("\n");
    }

    BIO_free(bio);
    printf("=================================\n\n");
}

SSL_CTX* create_context() {
    printf("\n[SSL Context Creation Phase]\n");
    printf("Creating SSL context with TLS_client_method()...\n");
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("Failed to create SSL context!\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("SSL context created successfully.\n");

    // 设置验证模式
    printf("Configuring client to verify server certificate...\n");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    // 加载系统默认CA证书
    printf("Loading system default CA certificates...\n");
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        printf("Failed to load system default CA certificates!\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1) {
        printf("Failed to load CA certificate (ca.crt)!\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* 加载客户端证书 */
    printf("\n[Client Certificate Loading Phase]\n");
    printf("Loading client certificate and private key...\n");
    // 加载客户端证书
    if (SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM) <= 0) {
        printf("Failed to load client certificate (client.crt)!\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("Client certificate loaded successfully.\n");

    // 加载客户端私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM) <= 0) {
        printf("Failed to load client private key (client.key)!\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("Client private key loaded successfully.\n");

    // 验证私钥是否匹配证书
    if (!SSL_CTX_check_private_key(ctx)) {
        printf("Client certificate and private key do not match!\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("Client certificate and private key verified successfully.\n");

    return ctx;
}

int main() {
    printf("\n========== Starting SSL Client ==========\n");

    WSADATA wsa;
    SOCKET client_socket;
    struct sockaddr_in server;
    char buffer[BUFFER_SIZE];

    SSL_CTX* ctx;
    SSL* ssl;

    // 初始化OpenSSL 3.0+
    printf("\n[OpenSSL Provider Initialization Phase]\n");
    printf("Loading default provider...\n");
    OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) {
        fprintf(stderr, "Failed to load default provider\n");
        return 1;
    }
    printf("Default provider loaded successfully.\n");

    printf("Loading legacy provider (for older algorithms)...\n");
    OSSL_PROVIDER* legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy_provider) {
        printf("Warning: Failed to load legacy provider (some algorithms may not be available)\n");
    }
    else {
        printf("Legacy provider loaded successfully.\n");
    }

    // 创建SSL上下文
    ctx = create_context();

    // 初始化Winsock
    printf("\n[Winsock Initialization Phase]\n");
    printf("Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed. Error: %d\n", WSAGetLastError());
        return 1;
    }
    printf("Winsock initialized successfully.\n");

    // 创建套接字
    printf("\n[Socket Creation Phase]\n");
    printf("Creating client socket...\n");
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket. Error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("Client socket created successfully.\n");

    // 准备地址结构
    printf("\n[Server Address Preparation Phase]\n");
    printf("Preparing server address structure...\n");
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    // 转换IP地址
    printf("Converting server IP address %s...\n", SERVER_IP);
    if (InetPton(AF_INET, SERVER_IP, &server.sin_addr) != 1) {
        printf("Invalid address/Address not supported\n");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    printf("Server address prepared successfully.\n");

    // 连接到服务器
    printf("\n[Server Connection Phase]\n");
    printf("Attempting to connect to server %s:%d...\n", SERVER_IP, PORT);
    if (connect(client_socket, (struct sockaddr*)&server, sizeof(server)) < 0) {
        printf("Connect failed. Error: %d\n", WSAGetLastError());
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    printf("Successfully connected to server %s:%d\n", SERVER_IP, PORT);

    // SSL握手
    printf("\n[SSL Handshake Phase]\n");
    printf("Creating new SSL object...\n");
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);

    printf("Performing SSL handshake with server...\n");
    if (SSL_connect(ssl) <= 0) {
        printf("SSL handshake failed!\n");
        ERR_print_errors_fp(stderr);
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    else {
        printf("SSL/TLS connection established successfully.\n");
        printf("Protocol version: %s\n", SSL_get_version(ssl));
        printf("Cipher suite: %s\n", SSL_get_cipher(ssl));

        // 获取服务器证书
        X509* cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            print_certificate_info(cert);

            // 验证证书
            long verify_result = SSL_get_verify_result(ssl);
            if (verify_result == X509_V_OK) {
                printf("Server certificate verification successful\n");
            }
            else {
                printf("Server certificate verification failed: %s (%ld)\n",
                    X509_verify_cert_error_string(verify_result), verify_result);
            }

            X509_free(cert);
        }
        else {
            printf("Warning: No server certificate provided!\n");
        }
    }

    // 通信循环
    printf("\n[Communication Phase]\n");
    printf("Entering communication loop. Type 'quit' to exit.\n");
    while (1) {
        // 发送消息
        printf("\nEnter message: ");
        fgets(buffer, BUFFER_SIZE, stdin);

        // 退出命令
        if (strcmp(buffer, "quit\n") == 0) {
            printf("Quitting...\n");
            break;
        }

        printf("Sending message to server...\n");
        int send_result = SSL_write(ssl, buffer, strlen(buffer));
        if (send_result <= 0) {
            printf("Failed to send message to server!\n");
            ERR_print_errors_fp(stderr);
            break;
        }
        printf("Successfully sent %d bytes to server\n", send_result);

        // 接收回复
        printf("Waiting for server reply...\n");
        int recv_size = SSL_read(ssl, buffer, BUFFER_SIZE);
        if (recv_size <= 0) {
            int err = SSL_get_error(ssl, recv_size);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
                printf("Server disconnected or SSL error occurred.\n");
                break;
            }
        }
        else {
            buffer[recv_size] = '\0';
            printf("Received %d bytes from server\n", recv_size);
            printf("Server reply: %s\n", buffer);
        }
    }

    // 清理资源
    printf("\n[Cleanup Phase]\n");
    printf("Shutting down SSL connection...\n");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    printf("Closing client socket...\n");
    closesocket(client_socket);
    printf("Freeing SSL context...\n");
    SSL_CTX_free(ctx);

    printf("Unloading OpenSSL providers...\n");
    OSSL_PROVIDER_unload(default_provider);
    if (legacy_provider) {
        OSSL_PROVIDER_unload(legacy_provider);
    }

    printf("Cleaning up OpenSSL resources...\n");
    EVP_cleanup();
    printf("Cleaning up Winsock...\n");
    WSACleanup();
    printf("\n========== Client Shutdown Completed ==========\n");

    return 0;
}