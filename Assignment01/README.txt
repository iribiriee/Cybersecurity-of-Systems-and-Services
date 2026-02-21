Assignment01 - 26/10/2025



----- What the tool does (brief) -----

server.c: TCP server with TLS that REQUIRES a client certificate (mutual TLS). It reads an XML login message and replies with a success XML if credentials are correct (sousi/123) or “Invalid Message” otherwise.

client.c: Legitimate TLS client that trusts the lab CA (ca.crt) and presents a client certificate (client.crt).

rclient.c: Rogue client that trusts a different CA (rogue_ca.crt) and presents a rogue certificate (rogue_client.crt). The server must reject it.

- How to compile (Linux/WSL)
gcc -Wall -o server server.c -lssl -lcrypto
gcc -Wall -o client client.c -lssl -lcrypto
gcc -Wall -o rclient rclient.c -lssl -lcrypto

- How to run
Server (listens on TCP port 8082):
./server 8082
Legit client (connect to localhost:8082):
./client 127.0.0.1 8082
Rogue client (should be rejected):
./rclient 127.0.0.1 8082
Note: 8082 is the TCP listening port number. You may use other ports; ports <1024 require sudo or CAP_NET_BIND_SERVICE.


Certificate/Key generation commands
Running all commands inside the project folder. The legit CA signs the server and the legit client. The rogue CA signs only the rogue client.




----- Certificates -----

1. Legitimate CA (used by server and legit client)
openssl genrsa -out ca.key 2048
genrsa: generate an RSA private key
-out ca.key: write key to file
2048: key size in bits

openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650
-subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECELab/CN=RootCA"
-out ca.crt
req: create a certificate request; with -x509 it creates a self-signed cert
-new: create new request/cert
-nodes: do not encrypt the private key
-key ca.key: sign with this private key
-sha256: use SHA-256 signature
-days 3650: certificate validity (10 years)
-subj "...": set DN non-interactively
-out ca.crt: write the CA certificate

2. Server certificate (signed by the legit CA)
openssl genrsa -out server.key 2048
openssl req -new -key server.key
-subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECELab/CN=localhost"
-out server.csr
-new: create a CSR
-key server.key: CSR signed by this private key
-subj: subject DN for the server (CN=localhost for local testing)
-out server.csr: write CSR

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial
-out server.crt -days 365 -sha256
x509 -req: sign a CSR to produce a certificate
-in server.csr: input CSR
-CA ca.crt: issuer CA certificate
-CAkey ca.key: issuer CA private key
-CAcreateserial: create ca.srl (serial file) if missing
-out server.crt: write server certificate
-days 365: cert validity (1 year)
-sha256: signature hash

3. Legitimate client certificate (signed by the legit CA)
openssl genrsa -out client.key 2048
openssl req -new -key client.key
-subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECELab/CN=client"
-out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial
-out client.crt -days 365 -sha256
(Parameters are the same as above but for the client identity.)

4. Rogue CA and Rogue client (different CA to demonstrate rejection)
openssl genrsa -out rogue_ca.key 2048
openssl req -x509 -new -nodes -key rogue_ca.key -sha256 -days 3650
-subj "/C=GR/ST=Crete/L=Chania/O=EvilLab/OU=Rogue/CN=RogueCA"
-out rogue_ca.crt
openssl genrsa -out rogue_client.key 2048
openssl req -new -key rogue_client.key
-subj "/C=GR/ST=Crete/L=Chania/O=EvilLab/OU=Rogue/CN=rogue_client"
-out rogue_client.csr
openssl x509 -req -in rogue_client.csr -CA rogue_ca.crt -CAkey rogue_ca.key -CAcreateserial
-out rogue_client.crt -days 365 -sha256
(These create a completely separate trust chain, the server does not trust rogue_ca.crt.)





----- Expected behavior -----

Legit client: mutual TLS handshake succeeds (server prints client Subject/Issuer) and XML exchange completes. Correct credentials return the provided XML body, wrong credentials return “Invalid Message”.

Rogue client: handshake fails because the server only trusts ca.crt, not rogue_ca.crt. The server rejects the rogue client before any application data is exchanged.




----- Requirements (from project description) -----

1. First run the server (e.g., ./server 8082) — Questions
a) What is the number 8082?
It’s the TCP listening port number for your server process—the socket is bound to port 8082 so clients know which port to connect to. 

b) Can you run it on 80, 443, 124? How can you achieve it?
Yes. Those are also TCP port numbers. You can start the server with any of them (e.g., ./server 80, ./server 443, or ./server 124).

However:
• Ports 80 and 443 are “well-known” ports typically requiring elevated privileges on many systems (ports <1024 often need root or CAP_NET_BIND_SERVICE). 
• Port 124 is a high (non-privileged) port and usually works without sudo. 



2. Then run the client (e.g., ./client 127.0.0.1 8082) — Questions
a) What is 127.0.0.1?
It’s the IPv4 loopback address (localhost). It tells the client to connect to a server running on the same machine. 

b) What is 8082?
It’s the server’s TCP port you chose in step (1); the client must use the same port to reach the listening server. 



3. Valid client request/response example
If the client sends a valid XML with the expected credentials, the server replies with the specified XML body. Example:

• Client request:
<Body><UserName>Sousi</UserName><Password>123</Password></Body>

• Server response:
<Body>
<Name>sousi.com</Name>
<year>1.5</year>
<BlogType>Embedede and c c++</BlogType>
<Author>John Johny</Author>
</Body>

(Your code accepts “sousi”/“123”, correct credentials → XML body response.)



4. Invalid client request/response example
If the client sends wrong credentials, the server must respond with “Invalid Message”. Example:

• Client request:
<Body><UserName>Sousi</UserName><Password>12345</Password></Body>

• Server response:
Invalid Message 



5. Rogue client behavior
If the rogue client (with a certificate signed by an unknown/untrusted CA) attempts to connect, the server must reject it and indicate that the peer did not present a valid certificate. Expected server output:
peer did not return a certificate or returned an invalid one
