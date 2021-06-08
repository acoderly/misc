/*
all:
        gcc -m32 -c -fno-builtin tiny_hello_world.c
        ld -m elf_i386 -static -e nomain -o tiny_hello_world.bin tiny_hello_world.o
clean:
        rm -f tiny_hello_world.o tiny_hello_world.bin
*/
char* str = "Hello, world!\n";

void print()
{
        asm(
                "movl $13, %%edx \n\t"
                "movl %0, %%ecx \n\t"
                "movl $0, %%ebx \n\t"
                "movl $4, %%eax \n\t"
                "int $0x80      \n\t"
                ::"r"(str):"edx","ecx","ebx");

}

void exit()
{
        asm(
                "movl $42, %%ebx        \n\t"
                "movl $1, %%eax         \n\t"
                "int $0x80              \n\t"
                :::);

}

void nomain()
{
        print();
        exit();

}
