---
layout: default
title:  "Initial thought, let's go back to the basics"
date:   2022-11-22 13:26:40 +0100
category: asm
---

# (Initial thought) - getting back to the basics

> Every second, billions of assembly instructions are executed all over the world regardless of their feelings.

Welcome here, n0bits brings you his first thought.

Since I have started to study computer science I have always wanted to work on the machine level and 
I have always been curious about computer architecture under the hood, 
so I picked assembly as it's nearest language of the machine code.

Today I will explain some basic concepts that I have learnt through my journey of assembly and computer architecture in general.
I won't write prerequisites, if you're here you have probably some knowledge about computer science and C in general.
If it's not the case please feel free to refer to google and wikipedia or reach me and let me know if some concepts are not clear enough,
I'll be glad to discuss it.

```
    +---------+     +-----------------------+     +------------+
    | C code  +---->| Assembly instructions +---->|Machine code|
    +---------+     +-----------------------+     +------------+
```

## What is assembly anyway?

Assembly is the key component to understand your computer's hardware and software. It teaches you the relationship
between hardware and OS, and how the software communicate with the OS.
Unlike the high level languages like `C, C++, java...` assembly is machine dependent, meaning each machine has its own assembly instruction sets.

## Why learn assembly?

Well, there are various reasons to learn assembly as understanding computer architecture and OS, 
Sometimes certain program requires close interaction with computer architecture. That being said, using assembly,
you get accessibility of hardware, time efficiency, and finally freedom.

## General computer architecture

Before deep dive into assembly, one should first have some basic ideas of computer architecture and how they work.
Almost every computer (by computer I mean computer, smartphones, machines, etc...) uses an architecture
called the `Von Neumann` architecture, the idea is basically dividing computer up into two parts, the `CPU` and `memory`.

### Computer memory

The computer memory is numbered sequences of fixed-size storage locations. That means that each memory has the same size.
It's implemented that way for the sake of simplicity.
```
            +-------+-------+-------+-------+-------+-------+--------+
            | 0x0011| 0x0012| 0x0013| 0x0014| 0x0015| 0x0016| 0x0017 |
            +-------+-------+-------+-------+-------+-------+--------+
            | 0x0018| 0x0018| 0x0019| 0x001A| 0x001B| 0x001C| 0x001D |
            +-------+-------+-------+-------+-------+-------+--------+
                                        ...
```

#### What memory is used for?

It's used for numbers of different things, the result of all kind of calculations is stored in memory, `location of cursor`,
`size of each window on the screen`, `the shape of each letter`, etc...
But in the Von Neumann architecture not only computer's data is stored in the memory but also the program itself 
is stored in the memory too.

For a computer there is no difference between program and program's data, they both are stored and accessed the same way,
The only difference is how they're used by the computer.

### The CPU

Well, simply storing data in memory doesn't help that much. Here is where the CPU comes in, the CPU has a `fetch-execute`
which simply means the CPU fetch an instruction then executes it.

To accomplish this simple task the CPU has some elements:

* Program counter: holds the next instruction to execute.
* Instruction decoder: decodes the current instruction to execute.
* General-purpose registers (More on it later)
* Arithmetic and logic unit: is a digital circuit used to perform arithmetic and logic operations.

So basically, the program counter tells what to be executed next and the instruction decoder tells what the 
instruction means (addition, subtraction, multiplication, data movement, etc.).

### Registers

In addition, of memory the processor itself has some special high-speed memory locations called registers.
There are two kind of registers, general-purpose and special-purpose registers. Most of the computer's calculations
are happening within the general-registers, the special registers as their name suggests have very specific purposes (More on it later).

## Assembly structure

A processor can only execute machine code, though it would be pain in the ass to a human to write machine code,
So the assembly is a way to write machine code in a more human-readable way.
Assembly language uses mnemonics to make this task easier. Mnemonics represent symbolic instructions, and the raw data
represent the variables and constants.y

That being said, I feel already tired, so I will take a pause, in the next articles we're going to start writing code in assembly.
