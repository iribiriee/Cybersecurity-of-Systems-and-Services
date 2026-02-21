#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h> // For PATH_MAX

// Max entries we'll track for simplicity.
// A real app would use dynamic lists.
#define MAX_ENTRIES 4096

// Struct for the -s option 
struct DeniedAccess {
    int uid;
    char filename[PATH_MAX];
};

// Structs for the -i option
struct UserActivity {
    int uid;
    int mod_count;
    int access_count;
};

struct FileHash {
    char hash[65]; // SHA-256 hex string + null
};

void usage(void) {
    printf(
            "\n"
            "usage:\n"
            "\t./audit_monitor [options]\n"
            "Options:\n"
            "-s, Prints suspicious users (those with > 5 distinct denied accesses)\n"
            "-i <filename>, Prints activity report for <filename>\n"
            "-h, Help message\n\n"
            );
    exit(1);
}

// qsort comparator for -s
int compare_denied_access(const void *a, const void *b) {
    struct DeniedAccess *da1 = (struct DeniedAccess *)a;
    struct DeniedAccess *da2 = (struct DeniedAccess *)b;
    if (da1->uid != da2->uid) {
        return da1->uid - da2->uid;
    }
    return strcmp(da1->filename, da2->filename);
}

void list_unauthorized_accesses(FILE *log) {
    struct DeniedAccess *accesses = malloc(MAX_ENTRIES * sizeof(struct DeniedAccess));
	if (accesses == NULL) {
        printf("Error: Failed to allocate memory to analyze accesses.\n");
        return;
    }
    int access_count = 0;
    char line[PATH_MAX + 200]; // Extra space for other fields

    fseek(log, 0, SEEK_SET); // Rewind log file

    while (fgets(line, sizeof(line), log) && access_count < MAX_ENTRIES) {
        // Parse: UID,PID,Filename,Date,Time,Operation,Denied,Hash
        int uid, denied;
        char filename[PATH_MAX];
        
        char *token = strtok(line, ",");
        if (!token) continue;
        uid = atoi(token);

        token = strtok(NULL, ","); if (!token) continue; // pid
        token = strtok(NULL, ","); if (!token) continue; // filename
        strncpy(filename, token, PATH_MAX);

        token = strtok(NULL, ","); if (!token) continue; // date
        token = strtok(NULL, ","); if (!token) continue; // time
        token = strtok(NULL, ","); if (!token) continue; // op
        
        token = strtok(NULL, ","); if (!token) continue; // denied
        denied = atoi(token);

        if (denied == 1) {
            accesses[access_count].uid = uid;
            strncpy(accesses[access_count].filename, filename, PATH_MAX - 1);
			accesses[access_count].filename[PATH_MAX - 1] = '\0';
            access_count++;
        }
    }

    if (access_count == 0) {
        printf("No denied access events found.\n");
        return;
    }

    // Sort to group by user and then by filename
    qsort(accesses, access_count, sizeof(struct DeniedAccess), compare_denied_access);
/*
    // Count distinct accesses per user
    int user_counts[MAX_ENTRIES] = {0}; // Index = UID (bad assumption, but simple)
                                        // A hash map would be better.
                                        // Let's use a simple O(n) pass on sorted data.
*/
    printf("Suspicious Users (more than 5 distinct denied accesses):\n");
    
    int current_uid = accesses[0].uid;
    int distinct_count = 1;
    int found_suspicious = 0;

    for (int i = 1; i < access_count; i++) {
        if (accesses[i].uid != current_uid) {
            // Switching to a new user. Check the count for the previous user.
            if (distinct_count > 5) {
                printf("- UID: %d (%d distinct denied files)\n", current_uid, distinct_count);
                found_suspicious = 1;
            }
            // Reset for new user
            current_uid = accesses[i].uid;
            distinct_count = 1;
        } else {
            // Same user. Check if it's a new file.
            if (strcmp(accesses[i].filename, accesses[i-1].filename) != 0) {
                distinct_count++;
            }
        }
    }
    
    // Check the last user in the list
    if (distinct_count > 5) {
        printf("- UID: %d (%d distinct denied files)\n", current_uid, distinct_count);
        found_suspicious = 1;
    }

    if (!found_suspicious) {
        printf("No users found matching the criteria.\n");
    }

	free(accesses);
}

void  list_file_modifications(FILE *log, char *file_to_scan) {
    struct UserActivity users[MAX_ENTRIES];
    int user_count = 0;
    struct FileHash hashes[MAX_ENTRIES];
    int hash_count = 0;

    char line[PATH_MAX + 200];
    
    // Get absolute path for comparison
    char abs_path_to_scan[PATH_MAX];
    if (realpath(file_to_scan, abs_path_to_scan) == NULL) {
        printf("Error: Cannot resolve absolute path for file: %s\n", file_to_scan);
        return;
    }

    fseek(log, 0, SEEK_SET); // Rewind log file

    while (fgets(line, sizeof(line), log)) {
        // Parse: UID,PID,Filename,Date,Time,Operation,Denied,Hash
        int uid, op, denied;
        char filename[PATH_MAX];
        char hash[65];
        
        char *token = strtok(line, ",");
        if (!token) continue;
        uid = atoi(token);

        token = strtok(NULL, ","); if (!token) continue; // pid
        token = strtok(NULL, ","); if (!token) continue; // filename
        strncpy(filename, token, PATH_MAX);

        if (strcmp(filename, abs_path_to_scan) != 0) {
            continue; // Not the file we're looking for
        }

        token = strtok(NULL, ","); if (!token) continue; // date
        token = strtok(NULL, ","); if (!token) continue; // time
        
        token = strtok(NULL, ","); if (!token) continue; // op
        op = atoi(token);
        
        token = strtok(NULL, ","); if (!token) continue; // denied
        denied = atoi(token);
        
        token = strtok(NULL, "\n"); if (!token) continue; // hash
        strncpy(hash, token, 64);
        hash[64] = '\0';

        if (denied == 1) {
            continue; // Ignore denied accesses for this report
        }

        // Find or add user
        int user_idx = -1;
        for (int i = 0; i < user_count; i++) {
            if (users[i].uid == uid) {
                user_idx = i;
                break;
            }
        }
        if (user_idx == -1 && user_count < MAX_ENTRIES) {
            user_idx = user_count;
            users[user_idx].uid = uid;
            users[user_idx].access_count = 0;
            users[user_idx].mod_count = 0;
            user_count++;
        }

        if (user_idx != -1) {
            users[user_idx].access_count++;
            if (op == 2) { // 'written' 
                users[user_idx].mod_count++;

                // Check if hash is unique
                int hash_found = 0;
                for (int i = 0; i < hash_count; i++) {
                    if (strcmp(hashes[i].hash, hash) == 0) {
                        hash_found = 1;
                        break;
                    }
                }
                if (!hash_found && hash_count < MAX_ENTRIES && strcmp(hash, "N/A") != 0) {
                    strncpy(hashes[hash_count].hash, hash, 65);
                    hash_count++;
                }
            }
        }
    }

    printf("Activity Report for: %s\n", abs_path_to_scan);
    printf("--------------------------------------------\n");
    if (user_count == 0) {
        printf("No activity found for this file.\n");
        return;
    }

    printf("Users who accessed the file:\n");
    for (int i = 0; i < user_count; i++) {
        printf("- UID: %d (Total Accesses: %d, Modifications: %d)\n",
               users[i].uid, users[i].access_count, users[i].mod_count);
    }
    
    printf("\nTotal unique modifications (based on hash): %d\n", hash_count); 
}

int  main(int argc, char *argv[]) {
    int ch;
    FILE *log;

    if (argc < 2)
        usage();

    log = fopen("/tmp/access_audit.log", "r");
    if (log == NULL) {
        printf("Error opening log file \"%s\"\n", "/tmp/access_audit.log");
        return 1;
    }

    while ((ch = getopt(argc, argv, "hi:s")) != -1) {
        switch (ch) {
        case 'i':
            list_file_modifications(log, optarg);
            break;
        case 's':
            list_unauthorized_accesses(log);
            break;
        case 'h': // Handle help option
        default:
            usage();
        }
    }

    fclose(log);
    argc -= optind;
    argv += optind;

    return 0;
}