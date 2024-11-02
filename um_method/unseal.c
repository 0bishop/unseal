#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#define NOP 0x90
#define SYSCALL 0x0f, 0x05
#define MSEAL_SYSCALL 462

/*
    000011bc  48c7c0ce010000     mov     rax, 0x1ce
    000011c3  4889cf             mov     rdi, rcx
    000011c6  4c89c6             mov     rsi, r8
    000011c9  4c89ca             mov     rdx, r9
    000011cc  0f05               syscall 
*/

/*
    mprotect will return -EPERM only if the region is sealed.
*/

struct map_node {
    unsigned long start;
    unsigned long end;
    int perm;
    unsigned long offset;
    unsigned int dev_major;
    unsigned int dev_minor;
    unsigned long inode;
    char path[256];
    struct map_node *next;
};

typedef struct {
    pid_t pid;
    char *binary;
    bool is_pid;
    char **argv;
    struct map_node *maps;
} target_t;

void parse_args(int argc, char **argv, target_t *target) {   
    if (sscanf(argv[1], "%d", &target->pid) == 1) {
        target->is_pid = true;
        target->binary = NULL;
    } else {
        target->is_pid = false;
        target->binary = argv[1];
    }

    target->argv = malloc(sizeof(char *) * (argc));
    for (int i = 0; i < argc - 1; i++) {
        target->argv[i] = argv[i + 1];
    }
    target->argv[argc - 1] = NULL;
}

int init_trace(target_t *target) {
    if (!target->is_pid) {
        target->pid = fork();
        if (target->pid == 0) {
            // Child process
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
                perror("ptrace traceme");
                exit(1);
            }
            execvp(target->binary, target->argv);
            perror("execvp");
            exit(1);
        } else if (target->pid < 0) {
            perror("fork");
            return -1;
        }
    } else {
        if (ptrace(PTRACE_ATTACH, target->pid, NULL, NULL) == -1) {
            perror("ptrace attach");
            return -1;
        }
    }
    return 0;
}

static int str_to_perm(const char *perm_str) {
    int perm = 0;

    if (perm_str[0] == 'r')
        perm |= PROT_READ;
    if (perm_str[1] == 'w')
        perm |= PROT_WRITE;
    if (perm_str[2] == 'x')
        perm |= PROT_EXEC;
    return perm;
}

static struct map_node *create_node(unsigned long start, unsigned long end,
                                  const char *perms, unsigned long offset,
                                  unsigned int dev_major, unsigned int dev_minor,
                                  unsigned long inode, const char *path) {
    struct map_node *node = malloc(sizeof(struct map_node));
    if (!node) return NULL;
    
    node->start = start;
    node->end = end;
    node->perm = str_to_perm(perms);
    node->offset = offset;
    node->dev_major = dev_major;
    node->dev_minor = dev_minor;
    node->inode = inode;
    strncpy(node->path, path, sizeof(node->path) - 1);
    node->path[sizeof(node->path) - 1] = '\0';
    node->next = NULL;
    
    return node;
}

struct map_node *get_proc_maps(pid_t pid) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror("fopen");
        return NULL;
    }

    struct map_node *head = NULL;
    struct map_node *tail = NULL;

    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end, offset, inode;
        unsigned int dev_major, dev_minor;
        char perm[5], path[256] = {0};
        
        sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %255s",
               &start, &end, perm, &offset,
               &dev_major, &dev_minor, &inode, path);

        struct map_node *node = create_node(start, end, perm, offset, dev_major,
            dev_minor, inode, path);
        if (!node)
            continue;

        if (!head) {
            head = tail = node;
        } else {
            tail->next = node;
            tail = node;
        }
    }

    fclose(maps);
    return head;
}

void free_proc_maps(struct map_node *head) {
    struct map_node *current = head;
    while (current) {
        struct map_node *next = current->next;
        free(current);
        current = next;
    }
}

int patch_memory(pid_t pid, unsigned long addr, const unsigned char* content, size_t size) {
    long original = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
    if (original == -1) {
        perror("ptrace peektext");
        return -1;
    }

    long patched_data = original & ~((1L << (size * 8)) - 1);
    
    for (size_t i = 0; i < size; i++) {
        patched_data |= ((long)content[i] << (i * 8));
    }

    // Place patch
    if (ptrace(PTRACE_POKETEXT, pid, addr, patched_data) == -1) {
        perror("ptrace poketext");
        return -1;
    }

    return 0;
}

int call_syscall(pid_t pid, struct user_regs_struct *regs) {
    struct user_regs_struct orig_regs;
    int status;
    
    // Backup original registers
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) == -1) {
        perror("ptrace getregs");
        return -1;
    }

    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) {
        perror("ptrace setregs");
        return -1;
    }

    const unsigned char syscall_ins[] = {0x0f, 0x05};
    
    // Save original bytes
    long original = ptrace(PTRACE_PEEKTEXT, pid, regs->rip, NULL);
    if (original == -1) {
        perror("ptrace peektext");
        return -1;
    }

    // Write syscall instruction
    if (patch_memory(pid, regs->rip, syscall_ins, sizeof(syscall_ins)) == -1) {
        fprintf(stderr, "Failed to patch syscall instruction\n");
        return -1;
    }

    // Execute syscall
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
        perror("ptrace singlestep");
        return -1;
    }

    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }

    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Process not stopped after syscall\n");
        return -1;
    }

    struct user_regs_struct new_regs;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs) == -1) {
        perror("ptrace getregs");
        return -1;
    }

    long syscall_ret = (long)new_regs.rax;

    // Restore original bytes
    if (patch_memory(pid, regs->rip, (const unsigned char *)&original, sizeof(syscall_ins)) == -1) {
        fprintf(stderr, "Failed to restore original bytes\n");
        return -1;
    }

    // Restore original registers
    if (ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs) == -1) {
        perror("ptrace setregs");
        return -1;
    }

    return syscall_ret;
}


int patch_mseal(pid_t pid, struct user_regs_struct *regs) {
    if (regs->orig_rax == MSEAL_SYSCALL) {
        // Xor registers
        regs->orig_rax ^= regs->orig_rax;
        regs->rax ^= regs->rax;
        regs->rdi ^= regs->rdi;
        regs->rsi ^= regs->rsi;
        regs->rdx ^= regs->rdx;

        if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) {
            perror("ptrace setregs");
            return -1;
        }

        // Place NOPs
        patch_memory(pid, regs->rip - 2, (const unsigned char[]){NOP, NOP}, 2);

        // Execute NOPs
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        waitpid(pid, NULL, 0);

        // Restore SYSCALL
        patch_memory(pid, regs->rip - 2, (const unsigned char[]){SYSCALL}, 2);

        printf("[UNSEAL] Intercepted mseal syscall, patched.\n");
    }

    return 0;
}

void trace_syscalls(pid_t pid) {
    int status;
    struct user_regs_struct regs;

    while (1) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
            perror("PTRACE_SYSCALL");
            exit(EXIT_FAILURE);
        }

        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            break;
        }

        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            perror("PTRACE_GETREGS");
            exit(EXIT_FAILURE);
        }

        if (patch_mseal(pid, &regs) == -1) {
            fprintf(stderr, "Failed to patch syscall.\n");
        }

    }
}

void unload_ptrace(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("ptrace detach");
        exit(EXIT_FAILURE);
    }
}

static bool check_if_sealed(target_t *target) {
    bool is_sealed = false;
    
    target->maps = get_proc_maps(target->pid);
    if (!target->maps) {
        unload_ptrace(target->pid);
        fprintf(stderr, "Failed to get process maps\n");
        return false;
    }

    struct map_node *current = target->maps;
    while (current) {
        if (strstr(current->path, ".so") != NULL || strstr(current->path, "[vvar]") != NULL) {
            current = current->next;
            continue;
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, target->pid, NULL, &regs) == -1) {
            perror("ptrace getregs");
            continue;
        }

        regs.rax = 10;
        regs.orig_rax = 10;
        regs.rdi = current->start;
        regs.rsi = current->end - current->start;
        regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;

        int ret = call_syscall(target->pid, &regs);
        if (ret == -EPERM)
            is_sealed = true;

        // restore protection
        regs.rdx = current->perm;
        int ret2 = call_syscall(target->pid, &regs);
        if (ret2 == -EPERM)
            is_sealed = true;

        current = current->next;
    }

    if (is_sealed) {
        unload_ptrace(target->pid);
        free_proc_maps(target->maps);
        fprintf(stderr, "Memory region has already been sealed\n");
        fprintf(stderr, "Consider call the prog like : ./unseal <program> [args...]\n");
    } else {
        printf("[UNSEAL] Memory regions are not yet sealed.\n");
    }

    return is_sealed;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <pid | program> [args...]\n", argv[0]);
        return 1;
    }

    target_t target = {0};
    int status = 0;

    parse_args(argc, argv, &target);

    if (init_trace(&target) < 0)
        return 1;

    if (waitpid(target.pid, &status, 0) == -1) {
        perror("waitpid");
        return 1;
    }

    if (target.is_pid && check_if_sealed(&target))
        return 1;

    trace_syscalls(target.pid);

    free_proc_maps(target.maps);
    free(target.argv);

    return 0;
}
