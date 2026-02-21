#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>




unsigned char Name[1024];

void readString() {
	char buf[32];
	gets(Name);
        memcpy(buf, Name, strlen(Name));
        printf("Hello %s, have a nice day.\n", Name);

   	return;
}



int main(void) {


	printf("What is your name?\n");
        printf("%p",Name);
	readString();
	exit(0);
}
