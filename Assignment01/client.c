#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenConnection(const char *hostname, int port) {
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        abort();
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    if (sd < 0) {
        perror("socket");
        abort();
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Connection failed");
        close(sd);
        abort();
    }
    return sd;
}

SSL_CTX* InitCTX(void) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Load CA that issued the server certificate (to verify server) */
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1) {
        fprintf(stderr, "Failed to load CA file ca.crt\n");
        ERR_print_errors_fp(stderr);
        abort();
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    /* Optional: restrict legacy protocols */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile) {
    /* Load client certificate */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading client certificate from %s\n", CertFile);
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* Load client private key */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading client key from %s\n", KeyFile);
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* Verify match */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Client private key does not match the certificate public key\n");
        abort();
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <hostname> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *hostname = argv[1];
    int port = atoi(argv[2]);

    SSL_CTX *ctx = InitCTX();
    LoadCertificates(ctx, "client.crt", "client.key");

    int server = OpenConnection(hostname, port);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    if (SSL_connect(ssl) == FAIL) {
        fprintf(stderr, "SSL_connect failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(server);
        SSL_CTX_free(ctx);
        return 1;
    }

    /* Verify server certificate result */
    long verify = SSL_get_verify_result(ssl);
    if (verify != X509_V_OK) {
        fprintf(stderr, "Server certificate verification failed: %ld\n", verify);
        SSL_free(ssl);
        close(server);
        SSL_CTX_free(ctx);
        return 1;
    }

    char username[64], password[64];
    printf("Enter username: ");
    if (scanf("%63s", username) != 1) strcpy(username, "sousi");
    printf("Enter password: ");
    if (scanf("%63s", password) != 1) strcpy(password, "123");

    char msg[512];
    snprintf(msg, sizeof(msg),
             "<Body><UserName>%s</UserName><Password>%s</Password></Body>",
             username, password);

    if (SSL_write(ssl, msg, (int)strlen(msg)) <= 0) {
        fprintf(stderr, "SSL_write failed\n");
        ERR_print_errors_fp(stderr);
    } else {
        char buf[2048];
        int n = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("Server response:\n%s\n", buf);
        } else {
            fprintf(stderr, "SSL_read failed or connection closed\n");
            ERR_print_errors_fp(stderr);
        }
    }

    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
