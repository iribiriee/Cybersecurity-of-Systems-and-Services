#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h> // For flock
#include <openssl/evp.h>
#include <limits.h> // For PATH_MAX

// --- Original Function Pointers ---
// We need these for our helper functions to avoid recursion
static FILE* (*original_fopen)(const char*, const char*) = NULL;
static size_t (*original_fread)(void*, size_t, size_t, FILE*) = NULL;
static int (*original_fclose)(FILE*) = NULL;
static ssize_t (*original_readlink)(const char*, char*, size_t) = NULL;

// Helper to get absolute path from a FILE* stream
// This is for fwrite and fclose
static char* get_path_from_stream(FILE *stream) {
    if (!original_readlink) {
        original_readlink = dlsym(RTLD_NEXT, "readlink");
    }

    int fd = fileno(stream);
    if (fd == -1) {
        return NULL;
    }

    char proc_path[PATH_MAX];
    char *abs_path = malloc(PATH_MAX);
    if (!abs_path) return NULL;

    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    
    ssize_t len = original_readlink(proc_path, abs_path, PATH_MAX - 1);
    if (len != -1) {
        abs_path[len] = '\0';
        return abs_path;
    } else {
        free(abs_path);
        return NULL;
    }
}

// Helper to calculate SHA-256 hash of a file
static char* calculate_sha256(const char *path) {
    // Ensure we have the original function pointers
    if (!original_fopen) original_fopen = dlsym(RTLD_NEXT, "fopen");
    if (!original_fread) original_fread = dlsym(RTLD_NEXT, "fread");
    if (!original_fclose) original_fclose = dlsym(RTLD_NEXT, "fclose");

    if (!original_fopen || !original_fread || !original_fclose) {
        return strdup("N/A (dlsym_error)");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha256();
    
    FILE *f = original_fopen(path, "rb");
    if (f == NULL) {
        return strdup("N/A (cannot_open)");
    }

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);

    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = original_fread(buffer, 1, sizeof(buffer), f)) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    original_fclose(f);

    // Convert binary hash to hex string
    char *hex_hash = malloc((hash_len * 2) + 1);
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(hex_hash + (i * 2), "%02x", hash[i]);
    }
    hex_hash[hash_len * 2] = '\0';
    return hex_hash;
}

// Central logging function
static void log_event(const char *path, int operation, int denied_flag) {
    // 1. Get all required info
    uid_t uid = getuid();
    pid_t pid = getpid();
    
    // Get absolute path if not already provided
    char abs_path_buffer[PATH_MAX];
    char *abs_path = realpath(path, abs_path_buffer);
    if (!abs_path) {
        // If realpath fails (e.g., file doesn't exist yet), use the path as-is
        abs_path = (char*)path;
    }

    // Get UTC Date/Time
    time_t now = time(NULL);
    struct tm utc_time;
    gmtime_r(&now, &utc_time);
    char date_str[11]; // YYYY-MM-DD
    char time_str[9];  // HH:MM:SS
    strftime(date_str, sizeof(date_str), "%Y-%m-%d", &utc_time);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", &utc_time);

    // Get file hash
    char *hash_str;
    if (denied_flag == 1 || operation == 0) { // No hash if denied or just created
        hash_str = strdup("N/A");
    } else {
        hash_str = calculate_sha256(abs_path);
    }

    // 2. Open log file (append mode)
    // We must use the *original* fopen to avoid recursion
    if (!original_fopen) original_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE *log_file = original_fopen("/tmp/access_audit.log", "a");
    if (log_file == NULL) {
        // Cannot log, but must continue gracefully
        free(hash_str);
        return;
    }

    // 3. Lock the file for process-safe writing
    flock(fileno(log_file), LOCK_EX);

    // 4. Write the log entry (using a simple CSV format)
    fprintf(log_file, "%d,%d,%s,%s,%s,%d,%d,%s\n",
            uid,
            pid,
            abs_path,
            date_str,
            time_str,
            operation,
            denied_flag,
            hash_str);
    
    // 5. Unlock and close
    flock(fileno(log_file), LOCK_UN);
    
    // Must use original fclose
    if (!original_fclose) original_fclose = dlsym(RTLD_NEXT, "fclose");
    original_fclose(log_file);
    
    free(hash_str);
}

// --- Intercepted Functions ---

FILE * fopen(const char *path, const char *mode)  {
    // Load original fopen if not already loaded
    if (!original_fopen) {
        original_fopen = dlsym(RTLD_NEXT, "fopen");
    }

    // --- Pre-call logic ---
    int operation = 1; // Default: 'opened' 
    int denied_flag = 0;
    
    // Check for file existence before opening 
    struct stat st;
    int file_existed = (stat(path, &st) == 0);

    if (strchr(mode, 'w') || strchr(mode, 'a')) {
        if (!file_existed) {
            operation = 0; // 'created' 
        }
    }

    // --- Call original function ---
    FILE *original_fopen_ret = original_fopen(path, mode);

    // --- Post-call logic ---
    if (original_fopen_ret == NULL) {
        denied_flag = 1; // Operation failed 
    }

    // Log the event
    log_event(path, operation, denied_flag);

    return original_fopen_ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*original_fwrite)(const void*, size_t, size_t, FILE*) = NULL;
    if (!original_fwrite) {
        original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    }

    // --- Call original function ---
    size_t original_fwrite_ret = original_fwrite(ptr, size, nmemb, stream);

    // --- Post-call logic ---
    if (original_fwrite_ret > 0) {
        // Log only if write was successful
        char *path = get_path_from_stream(stream);
        if (path) {
            log_event(path, 2, 0); // 2 = 'written' 
            free(path);
        }
    }
    // We don't log 'denied' for fwrite as it operates on an already-open stream

    return original_fwrite_ret;
}

int fclose(FILE *stream) {
    static int (*original_fclose_func)(FILE*) = NULL;
    if (!original_fclose_func) {
        original_fclose_func = dlsym(RTLD_NEXT, "fclose");
    }

    // --- Pre-call logic ---
    // Get path *before* closing the stream
    char *path = get_path_from_stream(stream);

    // --- Call original function ---
    int original_fclose_ret = original_fclose_func(stream);

    // --- Post-call logic ---
    if (path && original_fclose_ret == 0) {
        log_event(path, 3, 0); // 3 = 'closed'
        free(path);
    }
    
    return original_fclose_ret;
}