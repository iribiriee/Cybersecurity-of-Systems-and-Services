Greeter: Greeter.c
	gcc -ansi -static -fno-stack-protector -z execstack -fno-pie -g -m32 Greeter.c -o Greeter

secure_greeter: Greeter_secure.c
	gcc -ansi -fno-stack-protector -g -m32 Greeter_secure.c -o SecGreeter

secure_greeter_aslr: Greeter_secure_ASLR.c
	gcc -ansi Greeter_secure_ASLR.c -fno-stack-protector -no-pie -Wl,-z,relro,-z,now -o SecGreeterASLR

clean:
	rm Greeter SecGreeter
