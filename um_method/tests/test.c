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
    printf("hello world\n");
    unsigned long start = (unsigned long)&main;
    size_t len = 0x1000;

    int result = mseal(start, len, 0);
    int result2 = mseal(start, len, 0);
    printf("Result: %d\n", result);
    printf("Result2: %d\n", result2);

    if (result == 0) {
        printf("Memory region sealed\n");
        void *align_start = (void *)((signed long) start & ~(sysconf(_SC_PAGESIZE) - 1));
        int ret = 0;
        if ((ret = mprotect(align_start, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE | PROT_EXEC)) == 0)
            printf("Memory region perm changed\n");
        else {
            printf("Failed to change memory region, error code: %d\n", ret);
            perror("mprotect");
        }

    } else {
        printf("Failed to seal memory region, error code: %d\n", result);
    }



    return 0;
}