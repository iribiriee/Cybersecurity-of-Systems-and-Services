#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>     
#include <sys/stat.h> 
#include <unistd.h>
#include <gmp.h>     
#include <sodium.h>   
#include <sys/resource.h>

//global random state for gmp.h
gmp_randstate_t g_randstate;

void print_menu(const char *prog_name) {
    printf("Usage: %s [mode] [options]\n", prog_name);
    printf("\nModes (select one):\n");
    printf("  -g length   Perform RSA key-pair generation (e.g., 1024, 2048, 4096)\n");
    printf("  -e          Encrypt input and store results to output\n");
    printf("  -d          Decrypt input and store results to output\n");
    printf("  -s          Sign input file and store signature to output\n");
    printf("  -v path     Verify signature (path to signature file) against input file\n");
    printf("  -a path     Performance analysis, write results to 'path'\n");
    printf("  -h          This help message\n");
    printf("\nOptions (required for -e, -d, -s, -v):\n");
    printf("  -i path     Path to the input file\n");
    printf("  -o path     Path to the output file (for -e, -d, -s)\n");
    printf("  -k path     Path to the key file\n");
}

//writes n and key (e or d) to a file in hex
int write_key_file(const char *filename, mpz_t n, mpz_t key) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("Failed to open key file for writing");
        return -1;
    }
    gmp_fprintf(fp, "%Zx\n", n);
    gmp_fprintf(fp, "%Zx\n", key);
    fclose(fp);
    return 0;
}

//reads n and key (e or d) from a file
int read_key_file(const char *filename, mpz_t n, mpz_t key) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Could not open key file %s\n", filename);
        return -1;
    }
    if (gmp_fscanf(fp, "%Zx\n", n) != 1) {
        fprintf(stderr, "Error: Failed to read n from key file.\n");
        fclose(fp);
        return -1;
    }
    if (gmp_fscanf(fp, "%Zx\n", key) != 1) {
        fprintf(stderr, "Error: Failed to read key (e/d) from key file.\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

//calculate SHA-256 hash of a file
int calculate_hash_file(const char *filename, unsigned char *hash_out) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Could not open input file %s for hashing.\n", filename);
        return -1;
    }
    crypto_hash_sha256_state state;
    unsigned char buffer[4096];
    size_t bytes_read;

    crypto_hash_sha256_init(&state);
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        crypto_hash_sha256_update(&state, buffer, bytes_read);
    }
    crypto_hash_sha256_final(&state, hash_out);

    fclose(fp);
    return 0;
}

//get current time
double get_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

//get peak memory usage
long get_peak_memory_kb() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss;
}

int key_generator(int key_length) {
    if (key_length != 1024 && key_length != 2048 && key_length != 4096) {
        fprintf(stderr, "Error: Key length must be 1024, 2048, or 4096.\n");
        return 1;
    }
    printf("Generating %d-bit RSA key pair...\n", key_length);
    mpz_t p, q, n, lambda, e, d, p_minus_1, q_minus_1, gcd;
    mpz_inits(p, q, n, lambda, e, d, p_minus_1, q_minus_1, gcd, NULL);
    int p_bits = key_length / 2;
    int q_bits = key_length - p_bits;
    // 1. & 2. Find p and q
    // Generate p
    do {
        mpz_urandomb(p, g_randstate, p_bits);
        mpz_setbit(p, p_bits - 1); // Ensure it has p_bits
        mpz_nextprime(p, p);
    } while (mpz_sizeinbase(p, 2) != p_bits);
    // Generate q, ensuring p != q
    do {
        mpz_urandomb(q, g_randstate, q_bits);
        mpz_setbit(q, q_bits - 1); // Ensure it has q_bits
        mpz_nextprime(q, q);
    } while (mpz_sizeinbase(q, 2) != q_bits || mpz_cmp(p, q) == 0);
    // 3. n = p * q
    mpz_mul(n, p, q);
    // 4. lambda(n) = (p-1) * (q-1)
    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_mul(lambda, p_minus_1, q_minus_1);
    // 5. Choose e = 65537 (standard prime)
    mpz_set_ui(e, 65537);
    // Check gcd(e, lambda) == 1
    mpz_gcd(gcd, e, lambda);
    if (mpz_cmp_ui(gcd, 1) != 0) {
        fprintf(stderr, "Error: e=65537 is not coprime to lambda. This is rare. Rerunning...\n");
        mpz_clears(p, q, n, lambda, e, d, p_minus_1, q_minus_1, gcd, NULL);
        return key_generator(key_length); // Try again
    }
    // 6. d = modular inverse of (e, lambda)
    if (mpz_invert(d, e, lambda) == 0) {
        fprintf(stderr, "Error: Failed to compute modular inverse.\n");
        mpz_clears(p, q, n, lambda, e, d, p_minus_1, q_minus_1, gcd, NULL);
        return 1;
    }
    // 7. & 8. Write keys to files
    char pub_filename[256];
    char priv_filename[256];
    snprintf(pub_filename, sizeof(pub_filename), "public_%d.key", key_length);
    snprintf(priv_filename, sizeof(priv_filename), "private_%d.key", key_length);
    if (write_key_file(pub_filename, n, e) != 0) {
        fprintf(stderr, "Error writing public key.\n");
    } else {
        printf("Generated %s\n", pub_filename);
    }
    if (write_key_file(priv_filename, n, d) != 0) {
        fprintf(stderr, "Error writing private key.\n");
    } else {
        printf("Generated %s\n", priv_filename);
    }
    printf("Key generation complete.\n");
    mpz_clears(p, q, n, lambda, e, d, p_minus_1, q_minus_1, gcd, NULL);
    return 0;
}

int do_encryption(const char *in_file, const char *out_file, const char *key_file) {
    mpz_t n, e, m, c;
    mpz_inits(n, e, m, c, NULL);

    if (read_key_file(key_file, n, e) != 0) {
        mpz_clears(n, e, m, c, NULL);
        return 1;
    }

    FILE *f_in = fopen(in_file, "rb");
    if (!f_in) {
        fprintf(stderr, "Error: Could not open input file %s\n", in_file);
        mpz_clears(n, e, m, c, NULL);
        return 1;
    }
    FILE *f_out = fopen(out_file, "wb");
    if (!f_out) {
        fprintf(stderr, "Error: Could not open output file %s\n", out_file);
        fclose(f_in);
        mpz_clears(n, e, m, c, NULL);
        return 1;
    }

    // Block size in: 1 byte less than n's byte size to ensure m < n
    size_t n_bits = mpz_sizeinbase(n, 2);
    size_t block_size_in = (n_bits / 8) - 1;
    // Block size out: full byte size of n
    size_t block_size_out = (n_bits + 7) / 8;

    unsigned char *in_buf = malloc(block_size_in);
    unsigned char *out_buf = malloc(block_size_out);
    size_t bytes_read;
    size_t bytes_written;

    while ((bytes_read = fread(in_buf, 1, block_size_in, f_in)) > 0) {
        // Import plaintext block
        mpz_import(m, bytes_read, 1, 1, 0, 0, in_buf);
        // Encrypt: c = m^e mod n
        mpz_powm(c, m, e, n);
        // Export ciphertext block
        memset(out_buf, 0, block_size_out); // Clear buffer
        mpz_export(out_buf, &bytes_written, 1, 1, 1, 0, c);
        // Pad with leading zeros (mpz_export is big-endian, so padding is at the front)
        // We write the *full* block_size_out, but need to shift the exported data
        if (bytes_written < block_size_out) {
            memmove(out_buf + (block_size_out - bytes_written), out_buf, bytes_written);
            memset(out_buf, 0, block_size_out - bytes_written);
        }
        if (fwrite(out_buf, 1, block_size_out, f_out) != block_size_out) {
            fprintf(stderr, "Error: Failed to write to output file.\n");
            break;
        }
    }
    printf("Encryption complete. Output in %s\n", out_file);
    free(in_buf);
    free(out_buf);
    fclose(f_in);
    fclose(f_out);
    mpz_clears(n, e, m, c, NULL);
    return 0;
}

int do_decryption(const char *in_file, const char *out_file, const char *key_file) {
    mpz_t n, d, m, c;
    mpz_inits(n, d, m, c, NULL);

    if (read_key_file(key_file, n, d) != 0) {
        mpz_clears(n, d, m, c, NULL);
        return 1;
    }
    
    FILE *f_in = fopen(in_file, "rb");
    if (!f_in) {
        fprintf(stderr, "Error: Could not open input file %s\n", in_file);
        mpz_clears(n, d, m, c, NULL);
        return 1;
    }
    FILE *f_out = fopen(out_file, "wb");
    if (!f_out) {
        fprintf(stderr, "Error: Could not open output file %s\n", out_file);
        fclose(f_in);
        mpz_clears(n, d, m, c, NULL);
        return 1;
    }

    //block size in: full byte size of n
    size_t n_bits = mpz_sizeinbase(n, 2);
    size_t block_size_in = (n_bits + 7) / 8;
    unsigned char *in_buf = malloc(block_size_in);
    unsigned char *out_buf = malloc(block_size_in);
    size_t bytes_read;
    size_t bytes_written;

    while ((bytes_read = fread(in_buf, 1, block_size_in, f_in)) > 0) {
        if (bytes_read != block_size_in) {
            fprintf(stderr, "Error: Corrupt input file. Not aligned to block size.\n");
            break;
        }
        //import ciphertext block
        mpz_import(c, bytes_read, 1, 1, 1, 0, in_buf);
        //decrypt: m = c^d mod n
        mpz_powm(m, c, d, n);
        //export plaintext block
        mpz_export(out_buf, &bytes_written, 1, 1, 0, 0, m);

        if (fwrite(out_buf, 1, bytes_written, f_out) != bytes_written) {
            fprintf(stderr, "Error: Failed to write to output file.\n");
            break;
        }
    }
    printf("Decryption complete. Output in %s\n", out_file);
    free(in_buf);
    free(out_buf);
    fclose(f_in);
    fclose(f_out);
    mpz_clears(n, d, m, c, NULL);
    return 0;
}

int do_signing(const char *in_file, const char *out_file, const char *key_file) {
    mpz_t n, d, hash_mpz, sig_mpz;
    mpz_inits(n, d, hash_mpz, sig_mpz, NULL);

    if (read_key_file(key_file, n, d) != 0) {
        mpz_clears(n, d, hash_mpz, sig_mpz, NULL);
        return 1;
    }

    //we calculate the SHA-256 hash of the input file
    //then import the hash into mpz_t variable and sign it (signature = hash^d mod n)
    //then save the signature as hex
    unsigned char hash[crypto_hash_sha256_BYTES];
    if (calculate_hash_file(in_file, hash) != 0) {
        mpz_clears(n, d, hash_mpz, sig_mpz, NULL);
        return 1;
    }
    mpz_import(hash_mpz, sizeof(hash), 1, 1, 0, 0, hash);
    mpz_powm(sig_mpz, hash_mpz, d, n);

    FILE *f_out = fopen(out_file, "w");
    if (!f_out) {
        fprintf(stderr, "Error: Could not open output file %s\n", out_file);
        mpz_clears(n, d, hash_mpz, sig_mpz, NULL);
        return 1;
    }
    gmp_fprintf(f_out, "%Zx\n", sig_mpz);
    fclose(f_out);

    printf("File signed. Signature stored in %s\n", out_file);

    mpz_clears(n, d, hash_mpz, sig_mpz, NULL);
    return 0;
}

int check_signature(const char *in_file, const char *key_file, const char *sig_file) {
    mpz_t n, e, sig_mpz, hash_orig_mpz, hash_prime_mpz;
    mpz_inits(n, e, sig_mpz, hash_orig_mpz, hash_prime_mpz, NULL);
    //check public key.
    if (read_key_file(key_file, n, e) != 0) {
        mpz_clears(n, e, sig_mpz, hash_orig_mpz, hash_prime_mpz, NULL);
        return 1;
    }
    //get signature from file
    FILE *f_sig = fopen(sig_file, "r");
    if (!f_sig) {
        fprintf(stderr, "Error: Could not open signature file %s\n", sig_file);
        mpz_clears(n, e, sig_mpz, hash_orig_mpz, hash_prime_mpz, NULL);
        return 1;
    }
    if (gmp_fscanf(f_sig, "%Zx", sig_mpz) != 1) {
        fprintf(stderr, "Error: Failed to read signature from file.\n");
        fclose(f_sig);
        mpz_clears(n, e, sig_mpz, hash_orig_mpz, hash_prime_mpz, NULL);
        return 1;
    }
    fclose(f_sig);
    //calculate SHA-256 hash of the plaintext
    unsigned char hash_orig[crypto_hash_sha256_BYTES];
    if (calculate_hash_file(in_file, hash_orig) != 0) {
        mpz_clears(n, e, sig_mpz, hash_orig_mpz, hash_prime_mpz, NULL);
        return 1;
    }
    mpz_import(hash_orig_mpz, sizeof(hash_orig), 1, 1, 0, 0, hash_orig);
    //check signature: hash' = signature^e mod n
    mpz_powm(hash_prime_mpz, sig_mpz, e, n);
    //compare hash' with original hash
    if (mpz_cmp(hash_prime_mpz, hash_orig_mpz) == 0) {
        printf("Signature is VALID\n");
    } else {
        printf("Signature is INVALID\n");
    }
    mpz_clears(n, e, sig_mpz, hash_orig_mpz, hash_prime_mpz, NULL);
    return 0;
}

//the actual analysis function
int perform_analysis(int key_length, const char *data_file, FILE *out_fp) {
    char pub_key[256], priv_key[256], enc_file[256], dec_file[256], sig_file[256];
    double start_time, end_time;
    long start_mem, end_mem;

    snprintf(pub_key, sizeof(pub_key), "public_%d.key", key_length);
    snprintf(priv_key, sizeof(priv_key), "private_%d.key", key_length);
    snprintf(enc_file, sizeof(enc_file), "perf_%d.enc", key_length);
    snprintf(dec_file, sizeof(dec_file), "perf_%d.dec", key_length);
    snprintf(sig_file, sizeof(sig_file), "perf_%d.sig", key_length);
    
    //creating keys for the analysis
    printf("Generating %d-bit keys for analysis...\n", key_length);
    if (key_generator(key_length) != 0) {
        fprintf(stderr, "Failed to generate keys for %d bits.\n", key_length);
        return -1;
    }

    fprintf(out_fp, "Key Length: %d bits\n", key_length);

    //check encryption
    start_mem = get_peak_memory_kb();
    start_time = get_time();
    do_encryption(data_file, enc_file, pub_key);
    end_time = get_time();
    end_mem = get_peak_memory_kb();
    fprintf(out_fp, "Encryption Time: %.2fs\n", end_time - start_time);
    fprintf(out_fp, "Peak Memory Usage (Encryption): %ld KB\n", (end_mem - start_mem) > 0 ? (end_mem - start_mem) : 0);
    //fprintf(out_fp, "Peak Memory Usage (Encryption): %ld KB\n", end_mem);

    //check decryption 
    start_mem = get_peak_memory_kb();
    start_time = get_time();
    do_decryption(enc_file, dec_file, priv_key);
    end_time = get_time();
    end_mem = get_peak_memory_kb();
    fprintf(out_fp, "Decryption Time: %.2fs\n", end_time - start_time);
    fprintf(out_fp, "Peak Memory Usage (Decryption): %ld KB\n", (end_mem - start_mem) > 0 ? (end_mem - start_mem) : 0);
    //fprintf(out_fp, "Peak Memory Usage (Decryption): %ld KB\n", end_mem);

    //use signature
    start_mem = get_peak_memory_kb();
    start_time = get_time();
    do_signing(data_file, sig_file, priv_key);
    end_time = get_time();
    end_mem = get_peak_memory_kb();
    fprintf(out_fp, "Signing Time: %.2fs\n", end_time - start_time);
    fprintf(out_fp, "Peak Memory Usage (Signing): %ld KB\n", (end_mem - start_mem) > 0 ? (end_mem - start_mem) : 0);
    //fprintf(out_fp, "Peak Memory Usage (Signing): %ld KB\n", end_mem);

    //check signature
    start_mem = get_peak_memory_kb();
    start_time = get_time();
    check_signature(data_file, pub_key, sig_file);
    end_time = get_time();
    end_mem = get_peak_memory_kb();
    fprintf(out_fp, "Verification Time: %.2fs\n", end_time - start_time);
    fprintf(out_fp, "Peak Memory Usage (Verification): %ld KB\n", (end_mem - start_mem) > 0 ? (end_mem - start_mem) : 0);
    //fprintf(out_fp, "Peak Memory Usage (Verification): %ld KB\n", end_mem);
    fprintf(out_fp, "\n");

    return 0;
}

/*
int check_performance(const char *out_file) {
    FILE *f_out = fopen(out_file, "w");
    if (!f_out) {
        fprintf(stderr, "Error: Could not open performance file %s\n", out_file);
        return 1;
    }

    //creating a data file to sign/encrypt
    const char *tmp_data_file = "perf_data.tmp";
    FILE *f_data = fopen(tmp_data_file, "wb");
    if (!f_data) {
        fprintf(stderr, "Error: Could not create temp data file.\n");
        fclose(f_out);
        return 1;
    }

    //we create dummy data to perform the analysis.
    unsigned char *data_buf = malloc(1024 * 1024);
    memset(data_buf, 'A', 1024 * 1024);
    fwrite(data_buf, 1, 1024 * 1024, f_data);
    free(data_buf);
    fclose(f_data);
    printf("Running performance analysis...\n");
    
    perform_analysis(1024, tmp_data_file, f_out);
    perform_analysis(2048, tmp_data_file, f_out);
    perform_analysis(4096, tmp_data_file, f_out);
    printf("Performance analysis complete. Results in %s\n", out_file);

    fclose(f_out);
    remove(tmp_data_file);
    return 0;
}
*/

int check_performance(const char *out_file) {
    FILE *f_out = fopen(out_file, "w");
    if (!f_out) {
        fprintf(stderr, "Error: Could not open performance file %s\n", out_file);
        return 1;
    }

    //creating a data file to sign/encrypt
    const char *tmp_data_file = "perf_data.tmp";
    FILE *f_data = fopen(tmp_data_file, "wb");
    if (!f_data) {
        fprintf(stderr, "Error: Could not create temp data file.\n");
        fclose(f_out);
        return 1;
    }

    // --- START OF FIX ---
    // We create dummy data (1MB) to perform the analysis, but write it in chunks
    // to avoid a single large malloc that pollutes peak memory readings.
    unsigned char *data_buf = malloc(4096); // 4KB chunk
    if (!data_buf) {
        fprintf(stderr, "Error: Malloc failed for perf data buf.\n");
        fclose(f_data);
        fclose(f_out); // Also close the output file
        return 1;
    }
    memset(data_buf, 'A', 4096);
    for (int i = 0; i < 256; i++) { // 256 * 4KB = 1MB
        if (fwrite(data_buf, 1, 4096, f_data) != 4096) {
            fprintf(stderr, "Error: Fwrite failed for perf data.\n");
            break;
        }
    }
    free(data_buf);
    fclose(f_data);
    // --- END OF FIX ---

    printf("Running performance analysis...\n");
    
    perform_analysis(1024, tmp_data_file, f_out);
    perform_analysis(2048, tmp_data_file, f_out);
    perform_analysis(4096, tmp_data_file, f_out);
    printf("Performance analysis complete. Results in %s\n", out_file);

    fclose(f_out);
    remove(tmp_data_file);
    return 0;
}

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium!\n");
        return 1;
    }
    //initializing gmp using seed = current time for maximum randomness.
    gmp_randinit_default(g_randstate);
    gmp_randseed_ui(g_randstate, (unsigned long)time(NULL));
    int opt;
    char mode = 0;
    char *in_path = NULL;
    char *out_path = NULL;
    char *key_path = NULL;
    char *sig_path = NULL; // -v
    int key_length = 0;    // -g
    char *perf_path = NULL; // -a

    while ((opt = getopt(argc, argv, "g:edsv:a:i:o:k:h")) != -1) {
        switch (opt) {
            case 'g': mode = 'g'; key_length = atoi(optarg); break;
            case 'e': mode = 'e'; break;
            case 'd': mode = 'd'; break;
            case 's': mode = 's'; break;
            case 'v': mode = 'v'; sig_path = optarg; break;
            case 'a': mode = 'a'; perf_path = optarg; break;
            case 'h': mode = 'h'; break;

            case 'i': in_path = optarg; break;
            case 'o': out_path = optarg; break;
            case 'k': key_path = optarg; break;
            default:
                print_menu(argv[0]);
                return 1;
        }
    }
    switch (mode) {
        case 'g':
            if (key_length == 0) {
                fprintf(stderr, "Error: -g requires a key length.\n");
                return 1;
            }
            return key_generator(key_length);

        case 'e':
            if (!in_path || !out_path || !key_path) {
                fprintf(stderr, "Error: -e requires -i, -o, and -k.\n");
                return 1;
            }
            return do_encryption(in_path, out_path, key_path);

        case 'd':
            if (!in_path || !out_path || !key_path) {
                fprintf(stderr, "Error: -d requires -i, -o, and -k.\n");
                return 1;
            }
            return do_decryption(in_path, out_path, key_path);

        case 's':
            if (!in_path || !out_path || !key_path) {
                fprintf(stderr, "Error: -s requires -i, -o, and -k.\n");
                return 1;
            }
            return do_signing(in_path, out_path, key_path);

        case 'v':
            if (!in_path || !key_path || !sig_path) {
                fprintf(stderr, "Error: -v requires -i, -k, and the signature path.\n");
                return 1;
            }
            return check_signature(in_path, key_path, sig_path);

        case 'a':
            if (!perf_path) {
                fprintf(stderr, "Error: -a requires an output path.\n");
                return 1;
            }
            return check_performance(perf_path);

        case 'h':
        default:
            print_menu(argv[0]);
            return 0;
    }
    gmp_randclear(g_randstate);
    return 0;
}