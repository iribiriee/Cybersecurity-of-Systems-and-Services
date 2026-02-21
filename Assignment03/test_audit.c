#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h> // For chmod

int main() 
{
    int i;
    size_t bytes;
    FILE *file;
    char filenames[5][7] = {"file_0", "file_1", 
                            "file_2", "file_3", "file_4"};

    printf("--- Test Audit Program Starting ---\n\n");

    // --- Test 1: Create and Write (Tests fopen-create, fwrite, fclose) ---
    printf("Test 1: Creating and writing to 5 files...\n");
    for (i = 0; i < 5; i++) {
        printf("  Creating %s\n", filenames[i]);
        file = fopen(filenames[i], "w+");
        if (file == NULL) 
            printf("  fopen error for %s\n", filenames[i]);
        else {
            char data[20];
            sprintf(data, "data_for_%s", filenames[i]);
            bytes = fwrite(data, strlen(data), 1, file);
            printf("  Wrote %zu bytes to %s\n", bytes, filenames[i]);
            fclose(file);
        }
    }
    printf("Test 1 Complete.\n\n");

    // --- Test 2: Open and Read (Tests fopen-open, fclose) ---
    printf("Test 2: Opening existing file 'file_0' for reading...\n");
    file = fopen("file_0", "r");
    if (file == NULL) {
        printf("  fopen error for file_0\n");
    } else {
        printf("  Successfully opened file_0.\n");
        fclose(file);
    }
    printf("Test 2 Complete.\n\n");

    // --- Test 3: Open and Modify (Tests fopen-open, fwrite, fclose) ---
    printf("Test 3: Appending to existing file 'file_1'...\n");
    file = fopen("file_1", "a");
    if (file == NULL) {
        printf("  fopen error for file_1\n");
    } else {
        const char *append_data = "...more data";
        bytes = fwrite(append_data, strlen(append_data), 1, file);
        printf("  Appended %zu bytes to file_1.\n", bytes);
        fclose(file);
    }
    printf("Test 3 Complete.\n\n");
    
    // --- Test 4: Denied Access (Tests denied_flag)  ---
    printf("Test 4: Testing denied access...\n");
    const char *denied_file = "no_access_file.txt";
    
    // Create the file first
    file = fopen(denied_file, "w");
    if (file) {
        fwrite("secret", 6, 1, file);
        fclose(file);
        printf("  Created '%s'.\n", denied_file);
    }

    // Remove all permissions
    if (chmod(denied_file, 0000) == -1) {
        perror("  chmod (remove perms) error");
    } else {
        printf("  Removed all permissions from '%s'.\n", denied_file);
    }

    // Attempt to open for reading (should fail)
    printf("  Attempting to open '%s' for reading (should be DENIED)...\n", denied_file);
    file = fopen(denied_file, "r");
    if (file == NULL) {
        printf("  Open failed as expected (permission denied).\n");
    } else {
        printf("  !! UNEXPECTED: Open succeeded.\n");
        fclose(file);
    }

    // Attempt to open for writing (should fail)
    printf("  Attempting to open '%s' for writing (should be DENIED)...\n", denied_file);
    file = fopen(denied_file, "w");
    if (file == NULL) {
        printf("  Open failed as expected (permission denied).\n");
    } else {
        printf("  !! UNEXPECTED: Open succeeded.\n");
        fclose(file);
    }
    
    // Clean up
    chmod(denied_file, 0644); // Restore perms to delete
    remove(denied_file);
    printf("  Cleaned up '%s'.\n", denied_file);
    printf("Test 4 Complete.\n\n");

    printf("--- Test Audit Program Finished ---\n");
    return 0;
}