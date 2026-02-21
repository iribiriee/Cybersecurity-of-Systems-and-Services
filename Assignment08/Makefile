CC = gcc
CFLAGS = -Wall -g

all: audit_logger.so audit_monitor

# 1. Compile the Shared Library (Logger)
# Needs -fPIC for position independent code
# Needs -ldl for dlsym (hooking)
# Needs -lssl -lcrypto for SHA256 hashing
audit_logger.so: audit_logger.c
	$(CC) $(CFLAGS) -fPIC -shared -o audit_logger.so audit_logger.c -ldl -lssl -lcrypto

# 2. Compile the Monitor Tool
audit_monitor: audit_monitor.c
	$(CC) $(CFLAGS) -o audit_monitor audit_monitor.c

# Clean up
clean:
	rm -f audit_logger.so audit_monitor