#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <syscall.h>

#define MSEAL_SYSCALL 462

int mseal(unsigned long start, size_t len, unsigned long flags) {
    int result = 0;
    int page_size = sysconf(_SC_PAGESIZE);
    unsigned long page_aligned_start = start & ~(page_size - 1);

    asm volatile(
        "mov $462, %%rax\n"
        "mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "syscall\n"
        "mov %%eax, %0\n"
        : "=r"(result)
        : "r"(page_aligned_start), "r"(len), "r"(flags)
        : "rax", "rdi", "rsi", "rdx");
    return result;
}

int main(void) {

    while (1)
    {
        sleep(5);
        printf("Looping\n");
        unsigned long start = (unsigned long)&main;
        unsigned long align_start = ((signed long) start & ~(sysconf(_SC_PAGESIZE) - 1));

        size_t len = 0x1000;

        mseal(align_start, len, 0);

        sleep(5);

        if (mprotect((void *)align_start, len, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
        {
            perror("mprotect");
        } else {
            printf("mprotect success\n");
        }

    }
    
    return 0;
}