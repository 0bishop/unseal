# Unseal (patch) mseal syscall

## Usermod Method :
*The Usermod code is disgusting be kind.*
*Everything has been coded in 3 hours so its still experimental*

```bash
cd um_method

make
```

### Runtime way :
```bash
# Will start it in a child process and patch it.
./runtime_unseal ./tests/testseal

# Will attach the Pid and 'try' to patch the seal.
sudo ./runtime_unseal $(pidof loop)
```

- If set using PID, it will detect if it has been already sealed.
- For the patch, it will just place NOPs, xor registers, execute and restore the syscall.

https://github.com/user-attachments/assets/3cf9f33b-8d53-4e08-bdec-693722ff1559

### Static way :
```bash
./static_unseal ./tests/testseal

# Set execution perm to the patched elf
chmod +x patched_testseal 

# Execute it with mseal patched
./patched_testseal 
```

- Will scan mseal syscall pattern with my own scanner imp
```c
"48 c7 c0 ce 01 00 00 48|4c 89 ?? 48|4c 89 ?? 48|4c 89 ?? 0f 05"
```

- And replace the pattern by a shellcode that will xor all registers (and fill the rest with NOPs for padding)

![Screenshot_2024-11-02-23-56-26_1920x1080](https://github.com/user-attachments/assets/763ee5ff-5b0f-4215-8b6c-c2ec1c989a1e)

*(I will flag glibc / musl function pattern when it will be released (maybe in v2.41 for GLIBC))*

https://github.com/user-attachments/assets/fe095432-9355-47a2-ad77-a796c58cec08

## Kernelmod Method :
```bash
cd km_method

make

# Load driver
sudo insmod target/driver.ko

./unseal $(pidof loop)

# Remove driver
sudo rmmod driver
```

- Iterates through each VMA in the process.
- Checks if the VMA has the VM_SEALED flag.
- If sealed, removes the seal flag using vm_flags_clear.

https://github.com/user-attachments/assets/03b3e844-bab4-4b35-9174-5e74cb8edc83



## Ressources :
- https://elixir.bootlin.com/linux/v6.11/source/mm/mseal.c
- https://elixir.bootlin.com/linux/v6.11/source/mm/mprotect.c
- https://syscalls.mebeim.net/?table=x86%2F64%2Fx64%2Flatest
