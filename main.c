/*
===============================================================================
                    LINUX KERNEL DEEP DIVE (REAL STYLE)
===============================================================================

Structure Based On:
- Linux Kernel 6.x architecture
- task_struct
- CFS scheduler concept
- Kernel module style
- Device driver skeleton

===============================================================================
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bhanu Kernel Lab");
MODULE_DESCRIPTION("Linux Kernel Deep Dive Example");

/* =============================================================================
   1️⃣ task_struct (Real Kernel Process Structure)
   =============================================================================

   Real Linux stores process info inside:
   struct task_struct
*/

void print_current_process(void)
{
    struct task_struct *task = current;

    printk(KERN_INFO "PID: %d\n", task->pid);
    printk(KERN_INFO "Process Name: %s\n", task->comm);
    printk(KERN_INFO "State: %ld\n", task->state);
}

/* =============================================================================
   2️⃣ CONTEXT SWITCH (CFS Concept)
   =============================================================================

   In Linux:
   schedule() → pick_next_task() → context_switch()
*/

void simulate_schedule(void)
{
    printk(KERN_INFO "Simulating CFS scheduling...\n");
}

/* =============================================================================
   3️⃣ SYSTEM CALL FLOW
   =============================================================================

   User → syscall instruction → entry_SYSCALL_64
   → do_syscall_64() → sys_* function
*/

asmlinkage long sys_example(void)
{
    printk(KERN_INFO "Custom syscall executed\n");
    return 0;
}

/* =============================================================================
   4️⃣ INTERRUPT HANDLING
   =============================================================================

   Real Kernel:
   - IDT (Interrupt Descriptor Table)
   - request_irq()
*/

static irqreturn_t my_interrupt_handler(int irq, void *dev_id)
{
    printk(KERN_INFO "Interrupt occurred: %d\n", irq);
    return IRQ_HANDLED;
}

/* =============================================================================
   5️⃣ MEMORY MANAGEMENT
   =============================================================================

   Linux uses:
   - Buddy Allocator
   - Slab Allocator
*/

void *kernel_memory;

void allocate_kernel_memory(void)
{
    kernel_memory = kmalloc(1024, GFP_KERNEL);
    if (kernel_memory)
        printk(KERN_INFO "Memory allocated\n");
}

/* =============================================================================
   6️⃣ SPINLOCK (SMP Safe)
   =============================================================================

   Used in multicore environments
*/

spinlock_t my_lock;

void critical_section(void)
{
    spin_lock(&my_lock);
    printk(KERN_INFO "Inside critical section\n");
    spin_unlock(&my_lock);
}

/* =============================================================================
   7️⃣ CHARACTER DEVICE DRIVER (REAL STYLE)
   =============================================================================
*/

#define DEVICE_NAME "bhanu_char_dev"

static int major;

static int dev_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "Device opened\n");
    return 0;
}

static ssize_t dev_read(struct file *file, char __user *buffer,
                        size_t len, loff_t *offset)
{
    char msg[] = "Hello from kernel\n";
    copy_to_user(buffer, msg, sizeof(msg));
    return sizeof(msg);
}

static struct file_operations fops =
{
    .owner = THIS_MODULE,
    .open = dev_open,
    .read = dev_read,
};

/* =============================================================================
   8️⃣ /proc FILE SYSTEM ENTRY
   =============================================================================
*/

static ssize_t proc_read(struct file *file, char __user *buf,
                         size_t count, loff_t *ppos)
{
    char data[] = "Kernel Info\n";
    return simple_read_from_buffer(buf, count, ppos, data, sizeof(data));
}

static const struct proc_ops proc_fops =
{
    .proc_read = proc_read,
};

/* =============================================================================
   9️⃣ MODULE INIT / EXIT
   =============================================================================
*/

static int __init kernel_module_init(void)
{
    printk(KERN_INFO "Kernel Module Loaded\n");

    spin_lock_init(&my_lock);

    print_current_process();
    simulate_schedule();
    allocate_kernel_memory();
    critical_section();

    major = register_chrdev(0, DEVICE_NAME, &fops);
    proc_create("bhanu_proc", 0, NULL, &proc_fops);

    return 0;
}

static void __exit kernel_module_exit(void)
{
    printk(KERN_INFO "Kernel Module Unloaded\n");

    unregister_chrdev(major, DEVICE_NAME);
    remove_proc_entry("bhanu_proc", NULL);

    kfree(kernel_memory);
}

module_init(kernel_module_init);
module_exit(kernel_module_exit);
