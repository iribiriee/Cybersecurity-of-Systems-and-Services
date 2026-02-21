Assignment 3: Access Control Logging

----------------------------------------------------------

- Project Overview:

This project implements a comprehensive access control auditing system for Linux. It consists of a shared library (`audit_logger.so`) that intercepts file operations to log system activity, and a monitoring tool (`audit_monitor`) to analyze these logs for suspicious behavior.

The system uses the `LD_PRELOAD` mechanism to inject custom logging logic into standard C library functions (`fopen`, `fwrite`, `fclose`) without modifying the target application's source code.



- File Descriptions:

1. `audit_logger.c` (The Interceptor Library)
This file compiles into `audit_logger.so`. It is the core of the audit system.

Key Implementation Details:
Function Interception: We use `dlsym(RTLD_NEXT, ...)` to obtain pointers to the original libc functions. This allows us to execute our logging logic and then pass control back to the original function to ensure the program continues running normally.

Recursion Prevention:
Logging events requires file I/O (writing to the log) and hashing requires reading files. To prevent infinite recursion (where the logger calls `fopen`, triggering the logger again), all internal helper functions use the original function pointers directly, bypassing our interceptors.

Concurrency Safety:
We utilize `flock(..., LOCK_EX)` on the log file file descriptor. This ensures that if multiple processes are writing to the log simultaneously, they do not corrupt the log file structure.

Path Resolution:
For `fopen`, we use `realpath()` to log absolute paths.
For `fwrite` and `fclose` (which operate on streams), we recover the filename by reading the symbolic link `/proc/self/fd/<fd>`.

Event Logic:
Creation vs. Opening:
We check `stat()` before `fopen()` to determine if a file previously existed, allowing us to distinguish between "Created" (0) and "Opened" (1) events.

Denied Access:
We inspect the return value of the original `fopen`. If it returns `NULL`, we flag the event as `Denied` (1).

Hashing:
SHA-256 hashes are calculated for all successful accesses using the OpenSSL EVP library.




2. `audit_monitor.c` (The Log Analyzer)
This tool parses the generated `/tmp/access_audit.log` to generate security reports.

Key Implementation Details:

Dynamic Memory Allocation:
To handle potential large log files without causing stack overflow errors, we allocate analysis structures on the heap using `malloc`.

Suspicious User Detection (`-s`):
The tool filters the log for `Denied` events.
It sorts entries by UID and Filename.
It iterates through the sorted list to count *distinct* filenames per user.
Users with >5 distinct denied files are flagged as suspicious.

File Activity Analysis (`-i`):
Tracks total access counts and modification counts (writes) for a specific file.
Calculates "unique modifications" by tracking the number of unique content hashes generated during write operations.




3. `test_audit.c`
A test designed to verify the logger's functionality.

Test Coverage:
Creates multiple files to test creation logging.
Writes to files to test modification logging and hashing.
Opens existing files to test read logging.

Permission Testing:
Explicitly removes permissions (`chmod 000`) from a target file and attempts to open it, verifying that the logger correctly captures "Denied" events.




4. Makefile
Automates the build process.

`make all`: Compiles the shared library and both executables.
`make run`: Executes the test harness with the library preloaded (`LD_PRELOAD`).
`make clean`: Removes binaries and the log file for a fresh start.


Compilation and Usage:

  1. Build the project:
     make
    

  2. Run the Test (Generates Log):
     make run
    

  3. Analyze Logs:
     Check for Suspicious Users:
         ./audit_monitor -s
        
     Analyze Specific File:
        ./audit_monitor -i <absolute_path_to_file>
