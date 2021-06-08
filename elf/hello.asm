/*
all:
        nasm -f elf32 hello.asm
        ld -m elf_i386 -e main -s -o hello hello.o

clean:
        rm -f hello hello.o
*/
section .text
        global main
main:
        mov edx, len
        mov ecx, msg
        mov ebx, 1
        mov eax, 4
        int 0x80
        mov eax, 1
        int 0x80
section .data
msg db "Hello, world!", 0xa
len equ $ - msg
