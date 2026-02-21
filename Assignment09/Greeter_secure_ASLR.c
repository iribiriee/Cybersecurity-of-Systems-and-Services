#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>




char Name[256];
int grade = 5;
void readString() {
	char buf[32];
        puts("What is your name?");
	gets(buf);

        strcpy(Name, buf);

        printf("Hello ");
        printf(Name);
        printf(" your grade is %d have a nice day.\n", grade);
        gets(buf);
   	return;
}



int main(void) {

        setvbuf(stdout, NULL, _IONBF, 0);
	readString();
	exit(0);
}
