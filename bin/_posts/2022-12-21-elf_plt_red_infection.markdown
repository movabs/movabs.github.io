---
layout: default
title:  "Redirecting Shared Library Call Using PLT Infection"
date:   2022-12-21 15:03:00 +0100
category: bin
---

The ELF (Executable File Format) ABI (Application Binary Interface) is cool. It's so beautiful that when the compiler
writes a love letter to the linker about its precious objects, it uses ELF. When RTLD The RunTime LoaDer performs
its runtime relocation surgery, it goes by ELF, when the kernel writes epitaph for an arrogant process, it uses ELF.

One can imagine a world where binutils would use their own separate formats, all alike, leaving us to navigate the maze,
or think of how ugly a binary format could turn out to be and how hard it would be to support.

When two parsers see two different structures in the same bunch of bytes trouble ensues. In February 2013, 
Google has fixed a critical vulnerability in Android where an adversary could modify an Android app without 
breaking its code signature due to parser differential. GitLab has lately found a bug in file upload due to
parser differential.

ELF is beautiful, but with its beauty comes great responsibility.
Turns out not all the different binutils component as well as Linux kernel see the same content in an ELF file.


