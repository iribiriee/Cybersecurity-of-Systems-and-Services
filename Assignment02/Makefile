# --- Variables ---

# Compiler
CC = gcc

# Compiler flags: -Wall (all warnings), -Wextra (extra warnings), -g (debug symbols), -std=c11 (C standard)
CFLAGS = -Wall -Wextra -g -std=c11

# Executable names (from assignment)
TARGET_ECDH = ecdh_assign_2
TARGET_RSA = rsa_assign_2

# Source files (assuming they match executable names)
SRC_ECDH = ecdh_assign_2.c
SRC_RSA = rsa_assign_2.c

# Required libraries (from assignment)
# [cite_start]libsodium for ECDH [cite: 6]
LIBS_ECDH = -lsodium
# [cite_start]GMP for RSA [cite: 6]
LIBS_RSA = -lgmp -lsodium -lrt

# --- Build Rules ---

# Phony targets don't represent files
.PHONY: all clean

# Default target: builds both executables
all: $(TARGET_ECDH) $(TARGET_RSA)

# Rule to build the ECDH executable
$(TARGET_ECDH): $(SRC_ECDH)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS_ECDH)

# Rule to build the RSA executable
$(TARGET_RSA): $(SRC_RSA)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS_RSA)

# Target to clean up compiled files
clean:
	@echo "Cleaning up compiled executables..."
	rm -f $(TARGET_ECDH) $(TARGET_RSA)