#include <stdio.h>

int read_req(FILE *p) {
	char buf[64];
	int i;

	fgets(buf, 512, p);
	i = atoi(buf);
	return i;
}

int main() {
	FILE *fp = fopen("shellcode", "r");
	int x = read_req(fp);

	printf("x = %d\n", x);
}
