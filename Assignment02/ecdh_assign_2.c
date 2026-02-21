#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sodium.h>

//custom function that converts binary to hex and then uses fprintf to write to the file.
void fprint_hex(FILE *fp, const char *title, const unsigned char *key, size_t key_len) {
    char *hex_buf = malloc(key_len * 2 + 1);
    if (!hex_buf) {
        perror("Failed to allocate memory for hex buffer");
        return;
    }
    sodium_bin2hex(hex_buf, key_len * 2 + 1, key, key_len);
    fprintf(fp, "%s\n", title);
    fprintf(fp, "%s\n", hex_buf);
    free(hex_buf);
}

//custom function that takes the hex defined key from user (for alice or bob)
//and converts it to binary using sodium_hex2bin function.
int parse_hex_key(unsigned char *key_bin, size_t key_len, const char *key_hex) {
    if (strncmp(key_hex, "0x", 2) == 0) {
        key_hex += 2;
    }
    size_t hex_len = strlen(key_hex);
    if (hex_len > key_len * 2) {
        fprintf(stderr, "Error: Provided hex key is too long.\n");
        return -1;
    }
    //--------------
    memset(key_bin, 0, key_len);

    // 2. Calculate the length in bytes and the padding required.
    size_t bin_len = (hex_len + 1) / 2;
    size_t start_pos = key_len - bin_len; // This pads with zeros to the left

    // 3. Write the parsed hex *at the end* of the buffer.
    if (sodium_hex2bin(key_bin + start_pos, bin_len, key_hex, hex_len, NULL, NULL, NULL) != 0) {
        fprintf(stderr, "Error: Invalid hex string provided for key.\n");
        return -1;
    }
    //--------------

    return 0;
}

void print_menu(const char *prog_name) {
    printf("Usage: %s -o <path> [-a <key>] [-b <key>] [-c <context>] [-h]\n", prog_name);
    printf("Options:\n");
    printf("  -o path    Path to output file\n");
    printf("  -a number  Alice's private key (optional, hexadecimal format)\n");
    printf("  -b number  Bob's private key (optional, hexadecimal format)\n");
    printf("  -c context Context string for key derivation (default: \"ECDH_KDF\")\n");
    printf("  -h         This help message\n");
}

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium!\n");
        return 1;
    }
    //vars for alice and bob public/private/shared keys
    unsigned char pk_alice[crypto_scalarmult_curve25519_BYTES];
    unsigned char sk_alice[crypto_scalarmult_curve25519_BYTES];
    unsigned char pk_bob[crypto_scalarmult_curve25519_BYTES];
    unsigned char sk_bob[crypto_scalarmult_curve25519_BYTES];
    unsigned char s_alice[crypto_scalarmult_curve25519_BYTES];
    unsigned char s_bob[crypto_scalarmult_curve25519_BYTES];
    unsigned char enc_key_alice[32];
    unsigned char mac_key_alice[32];
    unsigned char enc_key_bob[32];
    unsigned char mac_key_bob[32];

    char *output_path = NULL;
    char *alice_sk_hex = NULL;
    char *bob_sk_hex = NULL;
    const char *kdf_context = "ECDH_KDF"; 
    int opt;

    while ((opt = getopt(argc, argv, "o:a:b:c:h")) != -1) {
        switch (opt) {
            case 'o':
                output_path = optarg; 
                break;
            case 'a':
                alice_sk_hex = optarg; 
                break;
            case 'b':
                bob_sk_hex = optarg; 
                break;
            case 'c':
                kdf_context = optarg; 
                break;
            case 'h':
                print_menu(argv[0]); 
                return 0;
            default:
                printf("Invalid option! Use -h to print the help menu.\n");
                return 1;
        }
    }

    if (output_path == NULL) {
        fprintf(stderr, "Error: You must include the output file path (-o).\n");
        print_menu(argv[0]);
        return 1;
    }

    //random key for alice
    if (alice_sk_hex == NULL) {
        randombytes_buf(sk_alice, sizeof(sk_alice));
        crypto_scalarmult_curve25519_base(pk_alice, sk_alice);
    } else {
        //user given key
        if (parse_hex_key(sk_alice, sizeof(sk_alice), alice_sk_hex) != 0) {
            return 1;
        }
        crypto_scalarmult_curve25519_base(pk_alice, sk_alice);
    }

    //same for bob, put random key
    if (bob_sk_hex == NULL) {
        randombytes_buf(sk_bob, sizeof(sk_bob));
        crypto_scalarmult_curve25519_base(pk_bob, sk_bob);
    } else {
        //else, put the key from user.
        if (parse_hex_key(sk_bob, sizeof(sk_bob), bob_sk_hex) != 0) {
            return 1;
        }
        crypto_scalarmult_curve25519_base(pk_bob, sk_bob);
    }

    //using crypto_scalarmult_curve25519 to calculate the shared key.
    if (crypto_scalarmult_curve25519(s_alice, sk_alice, pk_bob) != 0) {
        fprintf(stderr, "Alice failed to compute shared secret.\n");
        return 1;
    }
    if (crypto_scalarmult_curve25519(s_bob, sk_bob, pk_alice) != 0) {
        fprintf(stderr, "Bob failed to compute shared secret.\n");
        return 1;
    }
    
    //calculating enc and mac keys. using ids 1 and 2
    crypto_kdf_derive_from_key(enc_key_alice, 32, 1, kdf_context, s_alice);
    crypto_kdf_derive_from_key(mac_key_alice, 32, 2, kdf_context, s_alice);
    crypto_kdf_derive_from_key(enc_key_bob, 32, 1, kdf_context, s_bob);
    crypto_kdf_derive_from_key(mac_key_bob, 32, 2, kdf_context, s_bob);

    FILE *fp = fopen(output_path, "w");
    if (fp == NULL) {
        perror("Failed to open output file");
        return 1;
    }

    fprint_hex(fp, "Alice's Public Key:", pk_alice, sizeof(pk_alice));
    fprint_hex(fp, "Bob's Public Key:", pk_bob, sizeof(pk_bob));

    fprint_hex(fp, "Shared Secret (Alice):", s_alice, sizeof(s_alice));
    fprint_hex(fp, "Shared Secret (Bob):", s_bob, sizeof(s_bob));

    if (sodium_memcmp(s_alice, s_bob, sizeof(s_alice)) == 0) {
        fprintf(fp, "Shared secrets match!\n"); //
    } else {
        fprintf(fp, "Shared secrets DO NOT match!\n");
    }

    fprint_hex(fp, "Derived Encryption Key (Alice):", enc_key_alice, sizeof(enc_key_alice));
    fprint_hex(fp, "Derived Encryption Key (Bob):", enc_key_bob, sizeof(enc_key_bob));

    if (sodium_memcmp(enc_key_alice, enc_key_bob, sizeof(enc_key_alice)) == 0) {
        fprintf(fp, "Encryption keys match!\n"); //
    } else {
        fprintf(fp, "Encryption keys DO NOT match!\n");
    }

    fprint_hex(fp, "Derived MAC Key (Alice):", mac_key_alice, sizeof(mac_key_alice));
    fprint_hex(fp, "Derived MAC Key (Bob):", mac_key_bob, sizeof(mac_key_bob));

    if (sodium_memcmp(mac_key_alice, mac_key_bob, sizeof(mac_key_alice)) == 0) {
        fprintf(fp, "MAC keys match!\n"); //
    } else {
        fprintf(fp, "MAC keys DO NOT match!\n");
    }
    
    fclose(fp);
    printf("ECDH key exchange complete. Output written to %s\n", output_path);
    return 0;
}