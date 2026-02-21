#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenListener(int port) {
    int sd;
    int opt = 1;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    if (sd < 0) {
        perror("socket");
        abort();
    }

    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Can't bind port");
        abort();
    }
    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

SSL_CTX* InitServerCTX(void) {
    /* OpenSSL init (works for 1.1+ and 3.x) */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Load CA that issued client certs (to verify clients) */
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1) {
        fprintf(stderr, "Failed to load CA file ca.crt\n");
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Require client certificate (mutual TLS) */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    /* Harden a bit: prefer server ciphers, disable old protocols if desired */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile) {
    /* Load server certificate */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading server certificate from %s\n", CertFile);
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* Load server private key */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading server key from %s\n", KeyFile);
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* Verify private key matches certificate */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Server private key does not match the certificate public key\n");
        abort();
    }
}

void ShowCerts(SSL* ssl) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        char subj[1024];
        char issuer[1024];
        X509_NAME_oneline(X509_get_subject_name(cert), subj, sizeof(subj));
        X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
        printf("Client certificate:\n  Subject: %s\n  Issuer : %s\n", subj, issuer);
        X509_free(cert);
    } else {
        printf("No client certificate presented.\n");
    }
}

int xml_extract(const char* xml, const char* tag, char* out, size_t outsz) {
    /* naive XML extraction: finds <tag>value</tag> */
    char open[64], close[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    const char *a = strstr(xml, open);
    const char *b = strstr(xml, close);
    if (!a || !b || b <= a) return 0;
    a += strlen(open);
    size_t len = (size_t)(b - a);
    if (len + 1 > outsz) len = outsz - 1;
    memcpy(out, a, len);
    out[len] = '\0';
    return 1;
}

void Servlet(SSL* ssl) {
    char buf[2048];
    int bytes;

    if (SSL_accept(ssl) == FAIL) {
        fprintf(stderr, "SSL_accept failed\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    /* If mutual TLS fails (no/invalid cert), verification result will reflect it */
    long verify_res = SSL_get_verify_result(ssl);
    if (verify_res != X509_V_OK) {
        const char *msg = "peer did not return a certificate or returned an invalid one\n";
        fprintf(stderr, "%s", msg);
        SSL_write(ssl, msg, (int)strlen(msg));
        int sd = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(sd);
        return;
    }

    ShowCerts(ssl);

    bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (bytes <= 0) {
        SSL_free(ssl);
        return;
    }
    buf[bytes] = '\0';
    printf("Client message:\n%s\n", buf);

    /* Parse credentials */
    char user[128] = {0}, pass[128] = {0};
    int ok_u = xml_extract(buf, "UserName", user, sizeof(user));
    int ok_p = xml_extract(buf, "Password", pass, sizeof(pass));

    /* Compare against predefined values per assignment (sousi/123) */
    /* Note: assignment text shows "Sousi" once and "sousi" elsewhere; we'll accept case-insensitively. */
    int valid = 0;
    if (ok_u && ok_p) {
        if ((strcasecmp(user, "sousi") == 0) && (strcmp(pass, "123") == 0)) {
            valid = 1;
        }
    }

    if (valid) {
        const char *resp =
            "<Body>\n"
            "<Name>sousi.com</Name>\n"
            "<year>1.5</year>\n"
            "<BlogType>Embedede and c c++</BlogType>\n"
            "<Author>John Johny</Author>\n"
            "</Body>\n";
        SSL_write(ssl, resp, (int)strlen(resp));
    } else {
        const char *resp = "Invalid Message";
        SSL_write(ssl, resp, (int)strlen(resp));
    }

    int sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    SSL_CTX *ctx = InitServerCTX();

    /* Load server cert/key (signed by CA) */
    LoadCertificates(ctx, "server.crt", "server.key");

    int server = OpenListener(port);
    printf("Server listening on port %d ...\n", port);

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        int client = accept(server, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("accept");
            continue;
        }
        printf("Connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        Servlet(ssl);  /* handles SSL handshake + app logic */
    }

    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
