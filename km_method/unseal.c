#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>

#define UNSEAL_IOC_MAGIC 'k'
#define UNSEAL_IOCTL_CHECK_PID _IOW(UNSEAL_IOC_MAGIC, 1, int)

int main(int argc, char **argv) {
    int fd, pid, ret;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    fd = open("/dev/unseal", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    pid = atoi(argv[1]);
    ret = ioctl(fd, UNSEAL_IOCTL_CHECK_PID, &pid);
    printf("Unsealed %d VMAs\n", ret);

    close(fd);
    return 0;
}
