# 🐧 real-Linux-kernel-style

> A hands-on C project that **simulates the real Linux kernel boot and execution flow** — from bootloader all the way to userland, system calls, interrupts, memory management, and drivers.  
> Built for students, developers, and OS enthusiasts who want to **understand how Linux actually works under the hood**.

---

## 📋 Table of Contents

- [About the Project](#about-the-project)
- [Linux Kernel Boot Flow](#linux-kernel-boot-flow)
- [What This Code Simulates](#what-this-code-simulates)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Build & Run](#build--run)
- [Concepts Explained](#concepts-explained)
  - [Bootloader](#1-bootloader)
  - [start_kernel()](#2-start_kernel)
  - [init_task](#3-init_task)
  - [Scheduler](#4-scheduler-activated)
  - [Userland](#5-userland-systemd--init)
  - [System Calls](#6-system-calls)
  - [Interrupts, Memory & Drivers](#7-interrupts--memory--drivers)
- [Learning Resources](#learning-resources)
- [Contributing](#contributing)
- [License](#license)

---

## About the Project

Most developers use Linux every day but rarely think about what happens in the **milliseconds between pressing the power button and seeing a shell prompt**. This project bridges that gap.

`real-Linux-kernel-style` is a **pure C simulation** of the Linux kernel's core startup and execution pipeline. It is **not** a real kernel — it runs in user space — but it **mirrors the architecture, naming conventions, and flow** of the actual Linux source code (found at [kernel.org](https://kernel.org)).

### Why this project?

- 📚 Learn OS internals without needing to patch a real kernel
- 🔬 Understand how `init`, `systemd`, scheduling, and syscalls connect
- 💡 See real Linux-style C code patterns (structs, function pointers, macros)
- 🧪 Experiment safely — no risk of bricking your system

---

## Linux Kernel Boot Flow

This is the exact flow this project models:

```
┌─────────────────────────────────────────────┐
│               BIOS / UEFI                   │
│  (Power ON → Firmware initializes hardware) │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│               BOOTLOADER                    │
│  (GRUB2 / LILO — loads kernel into memory)  │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│            start_kernel()                   │
│  (First C function the kernel runs)         │
│  Sets up memory, CPU, console, subsystems   │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│              init_task                      │
│  (PID 0 — the idle/swapper process)         │
│  The very first process, never exits        │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│          Scheduler Activated                │
│  (CFS — Completely Fair Scheduler)          │
│  Manages process time-sharing on CPU(s)     │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│       Userland  (systemd / init)            │
│  (PID 1 — the mother of all processes)      │
│  Mounts filesystems, starts services        │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│             System Calls                    │
│  (The bridge between user space & kernel)   │
│  read(), write(), fork(), exec(), mmap()…   │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│    Interrupts / Memory / Drivers            │
│  Hardware IRQs, page faults, DMA, I/O       │
└─────────────────────────────────────────────┘
```

---

## What This Code Simulates

| Kernel Concept       | Simulated In Code                              |
|----------------------|------------------------------------------------|
| `start_kernel()`     | Entry point function that initializes all subsystems |
| `init_task`          | A `task_struct`-style struct representing PID 0 |
| Scheduler            | Simple round-robin / priority queue logic      |
| `fork()` / `exec()`  | Process creation simulation                    |
| System calls         | Function dispatch table (like `sys_call_table`) |
| Interrupts (IRQs)    | Interrupt handler registration and invocation  |
| Memory Management    | Basic page/frame allocation simulation         |
| Device Drivers       | Abstracted driver `init` and `probe` functions |

---

## Project Structure

```
real-Linux-kernel-style/
│
├── main.c          # Entry point — simulates start_kernel() and full boot flow
├── .gitignore      # Ignores build artifacts
└── README.md       # You are here
```

> The entire simulation lives in `main.c`, keeping it beginner-friendly and easy to follow top-to-bottom, just like reading the kernel boot path sequentially.

---

## Getting Started

### Prerequisites

You need a C compiler. On any Linux/macOS system you likely already have `gcc`:

```bash
gcc --version
```

On Ubuntu/Debian:
```bash
sudo apt update && sudo apt install gcc -y
```

On Windows, use [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) or [MinGW](https://www.mingw-w64.org/).

---

### Build & Run

```bash
# 1. Clone the repository
git clone https://github.com/Bhanu99517/real-Linux-kernel-style.git

# 2. Enter the directory
cd real-Linux-kernel-style

# 3. Compile
gcc main.c -o kernel_sim

# 4. Run
./kernel_sim
```

You should see output that walks through each stage of the Linux boot flow printed to your terminal — like watching a kernel boot in slow motion.

---

## Concepts Explained

### 1. Bootloader

The bootloader (e.g., **GRUB2**) is the first software that runs after the BIOS/UEFI firmware. Its job is to:
- Find the Linux kernel image (usually `/boot/vmlinuz`)
- Load it into RAM
- Pass control to the kernel's entry point

**Real Linux source:** `arch/x86/boot/main.c`

---

### 2. `start_kernel()`

This is the **first C function** the Linux kernel executes. It initializes everything: memory zones, CPU features, the interrupt descriptor table (IDT), the scheduler, the VFS, and dozens of other subsystems.

```c
// Simplified representation
void start_kernel(void) {
    setup_arch();
    mm_init();
    sched_init();
    init_IRQ();
    console_init();
    rest_init(); // spawns init_task and kernel threads
}
```

**Real Linux source:** `init/main.c`

---

### 3. `init_task`

`init_task` is **PID 0**, also called the **swapper** or **idle process**. It is statically defined (not created by `fork()`), and it becomes the CPU's idle loop when no other process is runnable.

```c
// Kernel-style task struct
struct task_struct init_task = {
    .pid   = 0,
    .state = TASK_RUNNING,
    .comm  = "swapper",
};
```

**Real Linux source:** `init/init_task.c`

---

### 4. Scheduler Activated

The Linux scheduler (CFS — **Completely Fair Scheduler**) manages which process runs on which CPU and for how long. It uses a **red-black tree** ordered by "virtual runtime" to ensure fairness.

Key scheduler concepts:
- `schedule()` — picks the next task to run
- `context_switch()` — saves current CPU state, loads the next task's state
- **Time slice** — the amount of CPU time a process gets before being preempted

---

### 5. Userland (systemd / init)

After the kernel is ready, it spawns **PID 1** — the first user-space process. On modern Linux systems this is `systemd`. Its responsibilities:
- Mount filesystems (`/proc`, `/sys`, `/dev`)
- Start system services (networking, logging, SSH, etc.)
- Become the parent of all other user processes

---

### 6. System Calls

System calls (syscalls) are the **controlled gateway** from user programs into the kernel. User programs cannot directly access hardware — they must ask the kernel via syscalls.

```
User Program
    │
    │  write(fd, buf, len)
    ▼
sys_call_table[__NR_write]
    │
    ▼
Kernel: sys_write() → file operations → driver → hardware
```

Common syscalls: `read`, `write`, `open`, `close`, `fork`, `exec`, `mmap`, `exit`

**How to trace syscalls on your machine:**
```bash
strace ./your_program
```

---

### 7. Interrupts / Memory / Drivers

**Interrupts (IRQs):** Hardware signals the CPU asynchronously (e.g., keyboard press, network packet). The kernel registers **interrupt service routines (ISRs)** to handle them.

**Memory Management:**
- Virtual memory — every process sees its own address space
- Page tables — map virtual → physical addresses
- `kmalloc` / `vmalloc` — kernel memory allocators

**Device Drivers:**
- Every piece of hardware needs a driver
- Drivers register themselves at boot via `module_init()`
- They implement standard operations: `open`, `read`, `write`, `ioctl`, `release`

---

## Learning Resources

Want to go deeper? Here are the best free resources:

| Resource | Link |
|---|---|
| Linux Kernel Source Code | [https://elixir.bootlin.com/linux/latest/source](https://elixir.bootlin.com/linux/latest/source) |
| The Linux Kernel documentation | [https://www.kernel.org/doc/html/latest/](https://www.kernel.org/doc/html/latest/) |
| Linux Inside (free online book) | [https://0xax.gitbooks.io/linux-insides/](https://0xax.gitbooks.io/linux-insides/) |
| OSDev Wiki | [https://wiki.osdev.org/](https://wiki.osdev.org/) |
| Robert Love — Linux Kernel Development | Classic textbook on kernel internals |
| `strace` / `ltrace` | Trace syscalls and library calls live on your machine |

---

## Contributing

Contributions are welcome! If you want to add more subsystems, improve comments, or add new simulations:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/add-memory-simulation`
3. Commit your changes: `git commit -m "Add page allocator simulation"`
4. Push: `git push origin feature/add-memory-simulation`
5. Open a Pull Request

Ideas for contributions:
- [ ] Add a virtual file system (VFS) simulation
- [ ] Simulate the page fault handler
- [ ] Add a simple network stack stub
- [ ] Add inline comments explaining each line like a textbook
- [ ] Add a `Makefile` for easier builds

---

## License

This project is open source and available under the [MIT License](LICENSE).

---

<div align="center">

Made with ❤️ for learners who want to understand Linux from the inside out.

⭐ **Star this repo if it helped you learn something new!**

</div>
