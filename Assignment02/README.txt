Assignment 2: Cryptographic Implementations

-----------------------------------------------------

This project implements two cryptographic tools in C: ecdh_assign_2 for key exchange and rsa_assign_2 for RSA operations.

Using the Makefile, it will generate the ecdh_assign_2 and rsa_assign_2 executables, linking against libsodium and gmp as required.

Here is a revised README file that explains the code's functionality based specifically on the implementation details in your provided C files.

Assignment 2: Cryptographic Implementations
This project implements two cryptographic tools in C: ecdh_assign_2 for key exchange and rsa_assign_2 for RSA operations.


1. ecdh_assign_2 (Elliptic Curve Diffie-Hellman)
This tool implements ECDH key exchange using Curve25519.

Implementation Details

Key Handling (parse_hex_key):

Accepts optional hex strings for private keys.
Crucially, it zero-initializes the 32-byte key buffer before parsing.
It right-aligns the parsed hex data, effectively padding it with leading zeros to ensure a consistent 32-byte key format, even for short input strings.


Key Generation & Exchange:

Uses libsodium's crypto_scalarmult_curve25519_base to derive public keys from private keys.
Computes the shared secret using crypto_scalarmult_curve25519, where each party multiplies their private key with the other's public key.


Key Derivation (KDF):

Uses crypto_kdf_derive_from_key to derive two separate session keys from the single shared secret.
It uses a context string (default: "ECDH_KDF") and unique subkey IDs (1 for encryption, 2 for MAC) to ensure the derived keys are cryptographically independent.


Output:

Writes all keys (Alice's/Bob's public keys, shared secrets, derived encryption/MAC keys) to the specified output file in hexadecimal format.
Verifies that both parties calculated identical secrets and keys.




2. rsa_assign_2 (RSA Algorithm)
This tool implements RSA from scratch using the GMP library for arbitrary-precision arithmetic.

Implementation Details

Key Generation (-g):

Generates two large primes, p and q, using mpz_urandomb and mpz_nextprime.
Ensures p and q have the correct bit length (half the total key length) and that p != q.
Computes n = p * q and lambda = (p-1)*(q-1).
Uses a fixed public exponent e = 65537.
Computes the private exponent d as the modular multiplicative inverse of e modulo lambda.
Saves keys to files in hex format: standard output includes public_<length>.key and private_<length>.key.


Encryption (-e) & Decryption (-d):

Reads input files in binary blocks.
Block Size: Calculates a safe block size that is strictly less than the modulus n to ensure unique encryption.
Uses GMP's mpz_powm for modular exponentiation: c = m^e mod n (encrypt) and m = c^d mod n (decrypt).
Handles padding by explicitly managing buffer sizes during mpz_export to preserve leading zeros in decrypted data.


Digital Signatures (-s, -v):

Signing: Computes the SHA-256 hash of the entire input file using libsodium. It imports this hash as an integer and signs it using signature = hash^d mod n.
Verification: Decrypts the signature using the public key (hash' = signature^e mod n) and compares the resulting hash' to the freshly computed SHA-256 hash of the input file. Matches indicate a valid signature.


Performance Analysis (-a):

Creates a temporary 1MB file (written in 4KB chunks to avoid memory spikes).
Measures execution time using clock_gettime(CLOCK_MONOTONIC).
Measures peak memory using getrusage(RUSAGE_SELF).

Memory Note: The tool reports the peak resident set size (RSS) of the process. Because key generation is highly memory-intensive, it often sets the peak for the entire run, causing subsequent operations to report 0 KB increase in peak memory. This is an accurate reflection of process-level peak memory usage.




TASK 1:
Examples
 1) Random keys: ./ecdh_assign_2 -o output.txt

Output of file "output.txt":
Alice's Public Key:
c1370b20039cbfdc40ba0a8eb8caed03f11b0dbbdbb549169fb277c5835e8466
Bob's Public Key:
1fcb0556402319ab3aa34dd53ac5dabd47ac7284f7dc25a9bf0cf4e96c00ed38
Shared Secret (Alice):
3ed1f660ef6d4761024276423b19bf31e455e840a7ba07bbbbad6d4436025b37
Shared Secret (Bob):
3ed1f660ef6d4761024276423b19bf31e455e840a7ba07bbbbad6d4436025b37
Shared secrets match!
Derived Encryption Key (Alice):
b76b634a737eb5b91ddc9bdcc307449ffc3ef0035e31e6c2720065c43b582ab1
Derived Encryption Key (Bob):
b76b634a737eb5b91ddc9bdcc307449ffc3ef0035e31e6c2720065c43b582ab1
Encryption keys match!
Derived MAC Key (Alice):
aa8f0b293922f625d7a7de3e23134e4aa461c41ccf8c8e052de8ad5d24dcf10d
Derived MAC Key (Bob):
aa8f0b293922f625d7a7de3e23134e4aa461c41ccf8c8e052de8ad5d24dcf10d
MAC keys match!



2) With fixed keys: ./ecdh_assign_2 -o output.txt -a 0x1a2b3c -b 0x1a2cb7

Generated two output files to make sure that both Alice's and Bob's public keys are the ones provided by the instruction. This implementation is true for this project.

Output 1:
Alice's Public Key:
62c1d222a075f308e260e11c9d8981e1d577533f981f9df4f34b7439ef9e7a7a
Bob's Public Key:
9be6b6ba3cc79df428d908e7cfc67400041dc6b119b09656668ffc95ddaed141
Shared Secret (Alice):
ec7705ce91d7de5984782b635164c882f2e8da0f52dc34fd378edae1e8b56277
Shared Secret (Bob):
ec7705ce91d7de5984782b635164c882f2e8da0f52dc34fd378edae1e8b56277
Shared secrets match!
Derived Encryption Key (Alice):
f596417bc2b93889c17f90160e51c59e5cdeb8783cd61c37cf24249accf5ad48
Derived Encryption Key (Bob):
f596417bc2b93889c17f90160e51c59e5cdeb8783cd61c37cf24249accf5ad48
Encryption keys match!
Derived MAC Key (Alice):
b20ff0901c16b6e6131ca9324dafbffd9df0830545b7f3d316759e4e55a538e6
Derived MAC Key (Bob):
b20ff0901c16b6e6131ca9324dafbffd9df0830545b7f3d316759e4e55a538e6
MAC keys match!

Output 2:
Alice's Public Key:
62c1d222a075f308e260e11c9d8981e1d577533f981f9df4f34b7439ef9e7a7a
Bob's Public Key:
9be6b6ba3cc79df428d908e7cfc67400041dc6b119b09656668ffc95ddaed141
Shared Secret (Alice):
ec7705ce91d7de5984782b635164c882f2e8da0f52dc34fd378edae1e8b56277
Shared Secret (Bob):
ec7705ce91d7de5984782b635164c882f2e8da0f52dc34fd378edae1e8b56277
Shared secrets match!
Derived Encryption Key (Alice):
f596417bc2b93889c17f90160e51c59e5cdeb8783cd61c37cf24249accf5ad48
Derived Encryption Key (Bob):
f596417bc2b93889c17f90160e51c59e5cdeb8783cd61c37cf24249accf5ad48
Encryption keys match!
Derived MAC Key (Alice):
b20ff0901c16b6e6131ca9324dafbffd9df0830545b7f3d316759e4e55a538e6
Derived MAC Key (Bob):
b20ff0901c16b6e6131ca9324dafbffd9df0830545b7f3d316759e4e55a538e6
MAC keys match!




3) With custom context for KDF: ./ecdh_assign_2 -o output.txt -a 0x1a2b3c -b
0x1a2cb7 -c "koukou25"

Generated two output files, for the first file we used [-c "koukou25"], and for the second one [-c "lalalo"].
They have the same secret and public keys, however the derived encryption key and the derived MAC key are different, as the -c flag is different.

Output 1:
Alice's Public Key:
62c1d222a075f308e260e11c9d8981e1d577533f981f9df4f34b7439ef9e7a7a
Bob's Public Key:
9be6b6ba3cc79df428d908e7cfc67400041dc6b119b09656668ffc95ddaed141
Shared Secret (Alice):
ec7705ce91d7de5984782b635164c882f2e8da0f52dc34fd378edae1e8b56277
Shared Secret (Bob):
ec7705ce91d7de5984782b635164c882f2e8da0f52dc34fd378edae1e8b56277
Shared secrets match!
Derived Encryption Key (Alice):
2156c7ba41ea5572819da5d3cfe7b029c7d8d2e2926b4dac7bb43ce10f8ae804
Derived Encryption Key (Bob):
2156c7ba41ea5572819da5d3cfe7b029c7d8d2e2926b4dac7bb43ce10f8ae804
Encryption keys match!
Derived MAC Key (Alice):
73e0a15342e35992bc8e094517657ed7cedd11e49da146824f9517092de53913
Derived MAC Key (Bob):
73e0a15342e35992bc8e094517657ed7cedd11e49da146824f9517092de53913
MAC keys match!

Output 2:
Alice's Public Key:
62c1d222a075f308e260e11c9d8981e1d577533f981f9df4f34b7439ef9e7a7a
Bob's Public Key:
9be6b6ba3cc79df428d908e7cfc67400041dc6b119b09656668ffc95ddaed141
Shared Secret (Alice):
ec7705ce91d7de5984782b635164c882f2e8da0f52dc34fd378edae1e8b56277
Shared Secret (Bob):
ec7705ce91d7de5984782b635164c882f2e8da0f52dc34fd378edae1e8b56277
Shared secrets match!
Derived Encryption Key (Alice):
f596417bc2b93889c17f90160e51c59e5cdeb8783cd61c37cf24249accf5ad48
Derived Encryption Key (Bob):
f596417bc2b93889c17f90160e51c59e5cdeb8783cd61c37cf24249accf5ad48
Encryption keys match!
Derived MAC Key (Alice):
b20ff0901c16b6e6131ca9324dafbffd9df0830545b7f3d316759e4e55a538e6
Derived MAC Key (Bob):
b20ff0901c16b6e6131ca9324dafbffd9df0830545b7f3d316759e4e55a538e6
MAC keys match!



TASK 2:
Key Generation:
Works correctly

Encryption:
Works correctly

Decryption:
Works correctly

Signing :
Works correctly

Verification :
Works correctly

Performance:
Results:
Key Length: 1024 bits
Encryption Time: 0.22s
Peak Memory Usage (Encryption): 0 KB
Decryption Time: 3.57s
Peak Memory Usage (Decryption): 0 KB
Signing Time: 0.09s
Peak Memory Usage (Signing): 88 KB
Verification Time: 0.17s
Peak Memory Usage (Verification): 0 KB

Key Length: 2048 bits
Encryption Time: 0.40s
Peak Memory Usage (Encryption): 0 KB
Decryption Time: 11.23s
Peak Memory Usage (Decryption): 0 KB
Signing Time: 0.06s
Peak Memory Usage (Signing): 0 KB
Verification Time: 0.14s
Peak Memory Usage (Verification): 0 KB

Key Length: 4096 bits
Encryption Time: 0.38s
Peak Memory Usage (Encryption): 0 KB
Decryption Time: 37.01s
Peak Memory Usage (Decryption): 0 KB
Signing Time: 0.13s
Peak Memory Usage (Signing): 0 KB
Verification Time: 0.14s
Peak Memory Usage (Verification): 0 KB


The memory analysis shows 0 KB for most operations because the measurement method (getrusage) tracks the peak memory usage (a "high-water mark") for the entire program.

In the test, the key_generator() function runs first and is very memory-intensive, setting a high peak. The subsequent encryption and decryption operations use less memory than this peak. Since the "high-water mark" doesn't increase, the difference in peak memory (end_mem - start_mem) is correctly reported as 0 KB.

The non-zero values (e.g., 88 KB for 1024-bit signing) simply indicate an operation that used slightly more memory than the key generation, setting a new peak. The results are a correct and logical outcome of this measurement method.

