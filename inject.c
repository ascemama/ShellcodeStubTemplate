#include<windows.h>
#include<stdio.h> 
#include <stdlib.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <fcntl.h>

 
/* Compile VS studio developer X64 prompt
 cl.exe inject.c /link /subsystem:windows /entry:mainCRTStartup
*/

/* hexdump
C:\Users\antoine\Security\Tools\hexdump-2.0.2\hexdump.exe testAsm1
*/

/*
nasm: nasm -f win64 -o hello_world.obj hello_world.asm
nasm: nasm -f win64 testAsm1.asm
*/
void print_hex(const char *string)
{
        unsigned char *p = (unsigned char *) string;

        for (int i=0; i < strlen(string); ++i) {
                if (! (i % 16) && i)
                        printf("\n");

                printf("0x%02x ", p[i]);
        }
        printf("\n\n");
}
 
 
int main(int argc, char **argv) {

 
unsigned char abc[256]="";
const char* filename = "enc_shellcode.bin";

FILE* in_file = fopen(filename, "rb");
    if (!in_file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    struct stat sb;

    if (stat(filename, &sb) == -1) {
        perror("stat");
        exit(EXIT_FAILURE);
    }

    char* file_contents = malloc(sb.st_size);
    fread(file_contents, sb.st_size, 1, in_file);

    print_hex(file_contents);
 
    fclose(in_file);

printf("for debug");
void *exec = VirtualAlloc(0, sb.st_size+3, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(exec, file_contents, sb.st_size+1);

((void(*)())exec)();
return 0;


}
