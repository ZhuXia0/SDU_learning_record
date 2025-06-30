#define _CRT_SECURE_NO_WARNINGS
#pragma once
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/applink.c>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define PORT 8080
#define BUFFER_SIZE 1024

void init_openssl() {
    printf("Initializing OpenSSL library...\n");
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    printf("OpenSSL initialization completed.\n");
}

void cleanup_openssl() {
    printf("Cleaning up OpenSSL resources...\n");
    EVP_cleanup();
    printf("OpenSSL cleanup completed.\n");
}

SSL_CTX* create_context() {
    printf("Creating SSL context...\n");
    const SSL_METHOD* method = SSLv23_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        printf("Failed to create SSL context!\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("SSL context created successfully.\n");
    return ctx;
}

int verify_callback(int preverify_ok, X509_STORE_CTX* ctx) {
    if (!preverify_ok) {
        int err = X509_STORE_CTX_get_error(ctx);
        printf("Certificate verification error: %s (%d)\n",
            X509_verify_cert_error_string(err), err);
    }
    return preverify_ok;
}

void configure_context(SSL_CTX* ctx) {
    printf("Configuring SSL context with certificate and private key...\n");

    /* 检查证书和私钥文件是否存在 */
    FILE* cert_file = fopen("server.crt", "r");
    if (!cert_file) {
        printf("Unable to find server. ct certificate file \n");
        printf("Please ensure that the current directory contains the server-side certificate file and the corresponding server-side private key file");
        exit(EXIT_FAILURE);
    }
    fclose(cert_file);
    FILE* key_file = fopen("server.key", "r");
    if (!key_file) {
        printf("Unable to find server. key private key file \n");
        printf("Please ensure that the current directory contains the server-side certificate file and the corresponding server-side private key file");
        exit(EXIT_FAILURE);
    }
    fclose(key_file);

    /* 加载证书和私钥 */
    printf("Loading certificate file (server.crt)...\n");
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        printf("Failed to load certificate file!\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("Loading private key file (server.key)...\n");
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        printf("Failed to load private key file!\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* 添加双向认证配置 */
    printf("Configuring client certificate verification...\n");
    // 设置验证模式为要求客户端证书
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);

    // 加载CA证书用于验证客户端证书
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1) {
        printf("Failed to load CA certificate (ca.crt) for client verification!\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 设置客户端CA列表（可选）
    STACK_OF(X509_NAME)* list = SSL_load_client_CA_file("ca.crt");
    if (list != NULL) {
        SSL_CTX_set_client_CA_list(ctx, list);
    }

    printf("SSL context configuration completed successfully.\n");
}

int main() {
    WSADATA wsa;
    SOCKET server_socket, client_socket;
    struct sockaddr_in server, client;
    int client_len;
    char buffer[BUFFER_SIZE];
    WCHAR client_ip[INET_ADDRSTRLEN];

    SSL_CTX* ctx;
    SSL* ssl;

    printf("\n========== Starting SSL Server ==========\n");

    // 初始化OpenSSL
    printf("\n[OpenSSL Initialization Phase]\n");
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

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
    printf("Creating server socket...\n");
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket. Error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("Server socket created successfully.\n");

    // 准备地址结构
    printf("\n[Socket Binding Phase]\n");
    printf("Preparing server address structure...\n");
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);
    printf("Server will listen on port %d\n", PORT);

    // 绑定套接字
    printf("Binding socket to address...\n");
    if (bind(server_socket, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Bind failed. Error: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    printf("Socket binding completed successfully.\n");

    // 开始监听
    printf("\n[Server Listening Phase]\n");
    printf("Setting socket to listen mode...\n");
    listen(server_socket, 3);
    printf("Server is now listening for incoming connections on port %d...\n", PORT);

    // 接受连接
    printf("\n[Client Connection Phase]\n");
    printf("Waiting for client to connect...\n");
    client_len = sizeof(struct sockaddr_in);
    client_socket = accept(server_socket, (struct sockaddr*)&client, &client_len);
    if (client_socket == INVALID_SOCKET) {
        printf("Accept failed. Error: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    // 显示客户端信息
    InetNtop(AF_INET, &client.sin_addr, client_ip, INET_ADDRSTRLEN);
    wprintf(L"Connection accepted from client %s:%d\n", client_ip, ntohs(client.sin_port));
    printf("Connection accepted from client %s:%d\n", client_ip, ntohs(client.sin_port));

    // 建立SSL连接
    printf("\n[SSL Handshake Phase]\n");
    printf("Creating new SSL object...\n");
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);

    printf("Performing SSL handshake with client...\n");
    if (SSL_accept(ssl) <= 0) {
        printf("SSL handshake failed!\n");
        int err = SSL_get_error(ssl, 0);
        printf("SSL error: %d - %s\n", err, ERR_error_string(err, NULL));
        ERR_print_errors_fp(stderr);
    }
    else {
        printf("SSL connection established successfully.\n");

        // 更详细的证书检查
        X509* client_cert = SSL_get_peer_certificate(ssl);
        if (client_cert) {
            printf("=== Client Certificate Details ===\n");

            // 使用BIO替代直接输出到stdout
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio) {
                X509_NAME_print_ex(bio, X509_get_subject_name(client_cert), 0, XN_FLAG_ONELINE);

                // 获取打印结果
                char* subject = NULL;
                long len = BIO_get_mem_data(bio, &subject);
                if (len > 0) {
                    printf("Subject: %.*s\n", (int)len, subject);
                }
                else {
                    printf("Failed to print certificate subject\n");
                }
                BIO_free(bio);
            }
            else {
                printf("Failed to create BIO for certificate printing\n");
            }

            // 验证结果
            long verify_result = SSL_get_verify_result(ssl);
            if (verify_result == X509_V_OK) {
                printf("Client certificate verification successful\n");
            }
            else {
                printf("Client certificate verification failed: %s (%ld)\n",
                    X509_verify_cert_error_string(verify_result), verify_result);
            }

            X509_free(client_cert);
        }
        else {
            printf("No client certificate received! Possible reasons:\n");
            printf("1. Client has no certificate configured\n");
            printf("2. Client certificate was rejected by the server\n");
            printf("3. Certificate verification failed\n");
        }
    }

    // 通信循环
    printf("\n[Communication Phase]\n");
    printf("Entering communication loop. Press Ctrl+C to exit.\n");
    while (1) {
        // 接收客户端消息
        printf("\nWaiting for client message...\n");
        int recv_size = SSL_read(ssl, buffer, BUFFER_SIZE);
        if (recv_size <= 0) {
            int err = SSL_get_error(ssl, recv_size);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
                printf("Client disconnected or SSL error occurred.\n");
                break;
            }
        }
        else {
            buffer[recv_size] = '\0';
            printf("Received %d bytes from client\n", recv_size);
            printf("Client message: %s\n", buffer);
        }

        // 发送回复给客户端
        printf("Enter reply: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        int send_size = SSL_write(ssl, buffer, strlen(buffer));
        printf("Sent %d bytes to client\n", send_size);
    }

    // 清理资源
    printf("\n[Cleanup Phase]\n");
    printf("Shutting down SSL connection...\n");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    printf("Closing client socket...\n");
    closesocket(client_socket);
    printf("Closing server socket...\n");
    closesocket(server_socket);
    printf("Freeing SSL context...\n");
    SSL_CTX_free(ctx);
    cleanup_openssl();
    printf("Cleaning up Winsock...\n");
    WSACleanup();
    printf("\n========== Server Shutdown Completed ==========\n");

    return 0;
}