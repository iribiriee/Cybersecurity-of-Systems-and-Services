# Assignment 9: Systems and Services Security - Buffer Overflow Exploitation

Source Code:
Greeter.c
Greeter_secure.c
Greeter_secure_ASLR.c
shell_test.c

Exploit Scripts:
exploit_greeter.py (Phase 1 solution)
exploit_secgreeter.py (Phase 2 solution)
exploit_final.py (Phase 3 solution - using pwntools)

---

## Overview
This submission contains exploits for three different security levels of the `Greeter` application. The goal was to bypass various memory protections (No-Execute stack, ASLR) to achieve Arbitrary Code Execution and obtain a shell.

### Prerequisites
* **OS:** Linux (Ubuntu x86_64/x86)
* **Python Libraries:** `pwntools` is required for Phase 3.
    * Install via: `pip3 install pwntools`

---

## Phase 1: Greeter (Stack Overflow)
**Objective:** Execute shellcode via Stack Buffer Overflow on a 32-bit binary with an executable stack.

Compilation
The binary was compiled with stack protections disabled and the stack made executable:
```bash
gcc -m32 -g -fno-stack-protector -z execstack -no-pie Greeter.c -o Greeter

Exploitation Strategy
Vulnerability: gets() allows unlimited input into a fixed-size buffer.

Payload: A NOP sled + Shellcode is injected. The Return Address is overwritten to point to the NOP sled.

Execution: The script exploit_greeter.py generates the payload. setarch is used to disable ASLR for deterministic memory addresses.
Bash:
python3 exploit_greeter.py > payload
(cat payload; cat) | setarch $(uname -m) -R ./Greeter


## Phase 2: SecGreeter (Return-to-Libc)
**Objective:** Bypass DEP (Data Execution Prevention/NX Bit) on a 32-bit binary.

Compilation
The binary has a non-executable stack (default) but no stack canary:
Bash: gcc -m32 -fno-stack-protector -no-pie Greeter_secure.c -o SecGreeter

Exploitation Strategy
Vulnerability: gets() buffer overflow.

Technique: Return-to-Libc. Since code execution on the stack is blocked, we overwrite the Return Address to jump to the system() function in libc.

Gadgets: The payload includes the address of system(), a dummy return address (or exit()), and the address of the string "/bin/sh". These addresses were identified using GDB.

Execution:
Bash
python3 exploit_secgreeter.py > payload_sec
(cat payload_sec; cat) | setarch $(uname -m) -R ./SecGreeter


## Phase 3: SecGreeterASLR (Bypassing ASLR & DEP)
**Objective:** Bypass both ASLR and DEP on a 64-bit binary.

Compilation
Compiled as a standard 64-bit binary without stack canaries:
Bash:
gcc -fno-stack-protector -no-pie -fcf-protection=none Greeter_secure_ASLR.c -o Sec

Exploitation Strategy:
Vulnerabilities:
Format String Vulnerability (printf(Name)): Used to leak a memory address from the stack.
Buffer Overflow (gets(buf)): Used to inject the ROP chain.

Technique:
Info Leak: The script first sends %33$p to leak a return address from libc.

Calculation: The base address of libc is calculated dynamically (Leak - Offset).

ROP Chain: A ROP chain is constructed using pwntools to pop the "/bin/sh" argument into the RDI register (x64 calling convention) and call system().

Execution: The script handles the process interaction automatically.
Bash:
python3 exploit_final.py