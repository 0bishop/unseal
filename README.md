# Unseal (patch) mseal syscall

## Usermod Method :

### Runtime :
```bash
# Will start it in a child process and patch it.
./unseal ./tests/testseal

# Will attach the Pid and 'try' to patch the seal.
sudo ./unseal $(pidof loop)
```

- If set using PID, it will detect if it has been already sealed.
- For the patch, it will just place NOPs, xor registers, execute and restore the syscall.

<video width="100%" controls>
  <source src="assets/2024-11-02-17-57-54.mp4" type="video/mp4">
</video>

### Static :
*to be continued*
(will certainly be accurate pattern scanning on glibc / musl function and syscall)

## Kernelmod Method :
```bash
# Load driver
sudo insmod target/driver.ko

./usermod $(pidof loop)

# Remove driver
sudo rmmod driver
```

- Iterates through each VMA in the process.
- Checks if the VMA has the VM_SEALED flag.
- If sealed, removes the seal flag using vm_flags_clear.

<video width="100%" controls>
  <source src="assets/2024-11-02-17-54-06.mp4" type="video/mp4">
</video>

## Ressources :
- https://elixir.bootlin.com/linux/v6.11/source/mm/mseal.c
- https://elixir.bootlin.com/linux/v6.11/source/mm/mprotect.c
- https://syscalls.mebeim.net/?table=x86%2F64%2Fx64%2Flatest
