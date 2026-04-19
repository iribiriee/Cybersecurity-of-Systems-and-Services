# Systems and Services Security 

This repository contains the coursework and projects for the **Systems and Services Security** (HPY 413) course at the ECE department of Technical University of Crete. The projects cover a wide range of security topics, including cryptography implementation, network security, intrusion detection, and malware analysis.

##  Assignments Overview
All required files and project descriptions are included for every assignment. 

### 1. Secure Server-Client Communication (OpenSSL)
Implementation of a secure client-server architecture using **C** and **OpenSSL**.
* **Key Concepts:** SSL/TLS Handshake, X.509 Certificates, Mutual TLS (mTLS).
* **Tech:** C, OpenSSL Library.

### 2. Cryptographic Implementations (RSA & ECDH)
Low-level implementation of two major cryptographic protocols:
* **ECDH:** Elliptic Curve Diffie-Hellman Key Exchange using `libsodium`.
* **RSA:** Key generation, encryption/decryption, and digital signatures using the `GMP` library.
* **Tech:** C, GMP, Libsodium.

### 3. Access Control Logging System
Development of an audit system that intercepts file operations to detect suspicious behavior.
* **Mechanism:** Uses `LD_PRELOAD` to override standard C library functions (`fopen`, `fwrite`, `fclose`).
* **Tools:** Custom Audit Logger (`.so` library) and Log Monitor.

### 4. Supply-Chain Malware Detection
Simulation of a supply-chain attack by modifying the **Paramiko** library used by **Fabric**.
* **Scenario:** Injecting malicious code into a trusted dependency.
* **Defense:** Detection using **OSSEC-HIDS** (file integrity monitoring) and **YARA** rules.

### 5. Web Vulnerabilities & Exploitation
Analysis and exploitation of a mock web application containing common vulnerabilities.
* **Attacks:** SQL Injection (SQLi), Reflected & DOM-based XSS, Local File Inclusion (LFI), Open Redirect.
* **Tech:** Python, Web Security.

### 6. Firewall Configuration (iptables)
A generic Bash script (`firewall.sh`) to automate packet filtering rules.
* **Features:** Blocking specific domains/IPs, saving/loading rulesets.
* **Tech:** Bash, Linux iptables/ip6tables.

### 7. Network Traffic Monitoring (Snort IDS)
Traffic analysis and intrusion detection using **Snort**.
* **Tasks:** Creating custom PCAP packets, writing Snort rules, and analyzing the **Slammer Worm** attack traffic.
* **Tech:** Snort, Wireshark, Python (Scapy).

### 8. Ransomware Simulation
Implementation of a ransomware workflow in a controlled Docker environment.
* **Functionality:** File encryption (OpenSSL), key management simulation, and file deletion.
* **Environment:** Docker (Ubuntu-based lab).
