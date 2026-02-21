#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <openssl/evp.h>

#define LOG_FILE_PATH "/home/student/data/access_audit.log"

void calculate_file_hash(const char *path, char *output_buffer) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        strcpy(output_buffer, "N/A");
        return;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    char buffer[4096];
    ssize_t bytes;

    EVP_DigestInit_ex(mdctx, md, NULL);
    while ((bytes = read(fd, buffer, sizeof(buffer))) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes);
    }
    EVP_DigestFinal_ex(mdctx, hash, &md_len);
    EVP_MD_CTX_free(mdctx);
    close(fd);

    for(unsigned int i = 0; i < md_len; i++) {
        sprintf(output_buffer + (i * 2), "%02x", hash[i]);
    }
    output_buffer[md_len * 2] = '\0';
}

void get_filename_from_fp(FILE *stream, char *buffer) {
    int fd = fileno(stream);
    char proc_path[64];
    sprintf(proc_path, "/proc/self/fd/%d", fd);
    ssize_t len = readlink(proc_path, buffer, PATH_MAX - 1);
    if (len != -1) {
        buffer[len] = '\0';
    } else {
        strcpy(buffer, "unknown");
    }
}

// --- SAFE LOG ACTION FUNCTION ---
void log_action(const char *path, int action_code, int denied) {
    uid_t uid = getuid();
    pid_t pid = getpid();

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    char hash_str[128];
    struct stat sb;

    // FIX: Only calculate hash if it is a REGULAR file (not a device/pipe)
    // and if the file actually exists.
    if (denied == 0 && stat(path, &sb) == 0 && S_ISREG(sb.st_mode)) {
        calculate_file_hash(path, hash_str);
    } else {
        strcpy(hash_str, "N/A");
    }

    int log_fd = open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (log_fd >= 0) {
        char log_entry[1024];
        sprintf(log_entry, "%d, %d, %s, %s, %d, %d, %s\n", 
                uid, pid, path, time_str, action_code, denied, hash_str);
        write(log_fd, log_entry, strlen(log_entry));
        close(log_fd);
    }
}

FILE *fopen(const char *path, const char *mode) 
{
    FILE *original_fopen_ret;
    FILE *(*original_fopen)(const char*, const char*);

    original_fopen = dlsym(RTLD_NEXT, "fopen");
    original_fopen_ret = (*original_fopen)(path, mode);

    char abs_path[PATH_MAX];
    if (realpath(path, abs_path) == NULL) {
        strncpy(abs_path, path, PATH_MAX);
    }

    int action = 1; 
    if (strstr(mode, "w") || strstr(mode, "a")) {
        action = 0; 
    }

    int denied = (original_fopen_ret == NULL) ? 1 : 0;

    log_action(abs_path, action, denied);

    return original_fopen_ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
    size_t original_fwrite_ret;
    size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

    char filename[PATH_MAX];
    get_filename_from_fp(stream, filename);
    
    if (strcmp(filename, LOG_FILE_PATH) != 0) {
        log_action(filename, 2, 0);
    }

    return original_fwrite_ret;
}

int fclose(FILE *stream)
{
    int original_fclose_ret;
    int (*original_fclose)(FILE*);

    char filename[PATH_MAX];
    get_filename_from_fp(stream, filename);

    original_fclose = dlsym(RTLD_NEXT, "fclose");
    original_fclose_ret = (*original_fclose)(stream);

    if (strcmp(filename, LOG_FILE_PATH) != 0) {
        log_action(filename, 3, 0);
    }

    return original_fclose_ret;
}