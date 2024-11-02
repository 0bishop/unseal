#include <linux/mm.h>
#include <linux/device.h>
#include <linux/cdev.h>

#define DEVICE_NAME "unseal"
#define UNSEAL_IOC_MAGIC 'k'
#define UNSEAL_IOCTL_CHECK_PID _IOW(UNSEAL_IOC_MAGIC, 1, int)

static dev_t dev;
static struct cdev cdev;
static struct class *dev_class;

static int rm_seal(struct task_struct *task) {
    struct mm_struct *mm = task->mm;
    struct vm_area_struct *vma;
    VMA_ITERATOR(vmi, mm, 0);
    int sealed_count = 0;

    mm = get_task_mm(task);
    if (!mm)
        return -ESRCH;

    for_each_vma(vmi, vma) {
        if (vma->vm_flags & VM_SEALED) {

            // Clear the flag
            vm_flags_clear(vma, VM_SEALED);
            pr_info("Unsealed VMA %lx-%lx\n", 
                   vma->vm_start, vma->vm_end);
            sealed_count++;
        }
    }

    mmput(mm);
    return sealed_count;
}

static long unseal_ioctl(struct file *file, unsigned int cmd, 
                        unsigned long arg) {
    struct task_struct *task;
    pid_t pid;
    int ret;

    if (cmd != UNSEAL_IOCTL_CHECK_PID)
        return -ENOTTY;

    if (copy_from_user(&pid, (void __user *)arg, sizeof(pid)))
        return -EFAULT;

    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!task)
        return -ESRCH;

    ret = rm_seal(task);
    put_task_struct(task);

    return ret;
}

static struct file_operations fops = {
    .unlocked_ioctl = unseal_ioctl,
    .owner = THIS_MODULE,
};

static int unseal_dev_uevent(const struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

static int __init mdriver_init(void) {
    // Allocate device numbers
    if ((alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME)) < 0) {
        pr_err("Cannot allocate major number\n");
        return -1;
    }

    // Initialize cdev structure
    cdev_init(&cdev, &fops);
    cdev.owner = THIS_MODULE;

    // Add device to system
    if ((cdev_add(&cdev, dev, 1)) < 0) {
        pr_err("Cannot add device to system\n");
        goto r_class;
    }

    // Create device class
    if (IS_ERR(dev_class = class_create("unseal_class"))) {
        pr_err("Cannot create struct class\n");
        goto r_class;
    }

    dev_class->dev_uevent = unseal_dev_uevent;

    // Create device node
    if (IS_ERR(device_create(dev_class, NULL, dev, NULL, DEVICE_NAME))) {
        pr_err("Cannot create device\n");
        goto r_device;
    }

    pr_info("Unseal driver loaded: Major=%d Minor=%d\n", MAJOR(dev), MINOR(dev));
    return 0;

r_device:
    class_destroy(dev_class);
r_class:
    unregister_chrdev_region(dev, 1);
    return -1;
}

static void __exit mdriver_exit(void) {
    device_destroy(dev_class, dev);
    class_destroy(dev_class);
    cdev_del(&cdev);
    unregister_chrdev_region(dev, 1);
    pr_info("Unseal driver unloaded\n");
}

module_init(mdriver_init);
module_exit(mdriver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bishop");
MODULE_DESCRIPTION("Unseal Memory Regions");