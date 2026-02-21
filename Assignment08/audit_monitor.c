#define _XOPEN_SOURCE 700
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>

#define BURST_THRESHOLD 5
#define BURST_TIME_WINDOW 1200 // 20 minutes

struct log_entry {
    int uid;
    int pid;
    char path[256];
    char date[32];
    char time[32];
    int access_type; 
    int denied;
    char hash[128];
    time_t timestamp;
};

void usage(void) {
    printf("\nusage:\n\t./audit_monitor [options]\nOptions:\n-v, Detect Ransomware\n-h, Help\n\n");
    exit(1);
}

int parse_log_line(char *line, struct log_entry *entry) {
    char *token;
    char line_copy[1024];
    strncpy(line_copy, line, sizeof(line_copy)); // Work on a copy

    // 1. UID
    token = strtok(line_copy, ","); if(!token) return 0; entry->uid = atoi(token);
    // 2. PID
    token = strtok(NULL, ","); if(!token) return 0; entry->pid = atoi(token);
    // 3. Path
    token = strtok(NULL, ","); if(!token) return 0;
    while(*token == ' ') token++; 
    strncpy(entry->path, token, sizeof(entry->path));
    
    // 4. Date Time
    token = strtok(NULL, ","); if(!token) return 0;
    char datetime[64];
    while(*token == ' ') token++;
    strncpy(datetime, token, sizeof(datetime));
    
    // 5. Action
    token = strtok(NULL, ","); if(!token) return 0; entry->access_type = atoi(token);
    // 6. Denied
    token = strtok(NULL, ","); if(!token) return 0; entry->denied = atoi(token);
    // 7. Hash
    token = strtok(NULL, ","); 
    if(token) {
        while(*token == ' ' || *token == '\n') token++;
        strncpy(entry->hash, token, sizeof(entry->hash));
    } else {
        strcpy(entry->hash, "N/A");
    }

    struct tm tm;
    memset(&tm, 0, sizeof(struct tm));
    if (strptime(datetime, "%Y-%m-%d %H:%M:%S", &tm) == NULL) {
        return 0; // Failed to parse time
    }
    entry->timestamp = mktime(&tm);
    return 1;
}

void detect_ransomware_activity(FILE *log) {
    char line[1024];
    struct log_entry entries[5000]; // Large buffer to catch everything
    int count = 0;

    printf("--- Ransomware Detection Report ---\n");

    rewind(log);
    while (fgets(line, sizeof(line), log)) {
        if (parse_log_line(line, &entries[count])) {
            count++;
            if(count >= 5000) break; 
        }
    }

    // CHECK 1: BURST DETECTION
    // We look for multiple .enc files being CLOSED (finished writing) in short time
    printf("\n[Check 1] High-Volume File Creation (Threshold: %d)\n", BURST_THRESHOLD);
    
    for (int i = 0; i < count; i++) {
        // Look for CLOSE (3) of a .enc file
        if (entries[i].access_type == 3 && strstr(entries[i].path, ".enc")) {
            int burst_count = 0;
            for (int j = i; j < count; j++) {
                if (entries[j].access_type == 3 && strstr(entries[j].path, ".enc")) {
                    double diff = difftime(entries[j].timestamp, entries[i].timestamp);
                    if (diff >= 0 && diff <= BURST_TIME_WINDOW) {
                        burst_count++;
                    }
                }
            }
            if (burst_count >= BURST_THRESHOLD) {
                printf("(!) ALERT: Burst detected! %d files encrypted starting at %s", 
                       burst_count, ctime(&entries[i].timestamp));
                i += burst_count; // Skip these to avoid duplicate alerts
            }
        }
    }

    // CHECK 2: ENCRYPTION WORKFLOW
    // Look for: CLOSE original file -> CLOSE .enc file (Sequence of events)
    printf("\n[Check 2] Encryption Workflow (Source -> Encrypted)\n");
    
    for (int i = 0; i < count; i++) {
        // Found a .enc file being closed?
        if (entries[i].access_type == 3 && strstr(entries[i].path, ".enc")) {
            
            // Deduce the original filename (remove .enc)
            char original_path[256];
            char *ext = strstr(entries[i].path, ".enc");
            int len = ext - entries[i].path;
            strncpy(original_path, entries[i].path, len);
            original_path[len] = '\0';

            // Check if the original file was also closed recently by the same PID
            for (int j = i - 1; j >= 0; j--) {
                if (entries[j].pid == entries[i].pid && 
                    entries[j].access_type == 3 && 
                    strcmp(entries[j].path, original_path) == 0) {
                    
                    printf("(!) ALERT: Encryption Pattern Detected!\n");
                    printf("    Original:  %s\n", original_path);
                    printf("    Encrypted: %s\n", entries[i].path);
                    break; 
                }
            }
        }
    }
    printf("-----------------------------------\n");
}

int main(int argc, char *argv[]) {
    int ch;
    FILE *log;

    if (argc < 2) usage();

    log = fopen("/home/student/data/access_audit.log", "r");
    if (log == NULL) {
        log = fopen("./access_audit.log", "r");
        if (!log) { printf("Error: Log file not found.\n"); return 1; }
    }

    while ((ch = getopt(argc, argv, "v")) != -1) {
        switch (ch) {
        case 'v':
            detect_ransomware_activity(log);
            break;
        default:
            usage();
        }
    }
    fclose(log);
    return 0;
}