# Write-up
## Recon
In this challenge we are given a single unstripped binary. The results of `file` and `pwn checksec` are below:

File:
```
vip_blacklist: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=50af2ef2ebbfe81e7281c668dc29a964a4f872a8, for GNU/Linux 3.2.0, not stripped
```
pwn checksec:
```javascript
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```
From this we can see that we are working with an x86-64 binary with most common midigations in effect. There are also two midigations I had not seen from `pwn checksec` before, those being `SHSTK` and `IBT`. `IBT` stands for Indirect Branch Tracking. It basically makes it so that all indirect jumps must be to an `endbr64` (in x86_64). This prevents jumping to a place the compiler was not expecting a jump to. I was not able to confirm this but I believe that `SHSTK` is short for shadow stack. This means that a seperate stack is kept along side the normal stack that tracks all return addresses. At the time of a `ret` instruction the saved return address on the main stack is compared against the saved return address on the shadow stack. If the two addresses are not equal, the program will crash. These midigations make any sort of ROP attack basically impossible, so we may have to get creative with our exploit. 

## Reversing
To find out what primatives we are working with we will now preform static analysis on the challenge binary.

### Static Analysis
To do this we can throw the binary into ghidra and see what the decompiler spits out. Upon loading the binary into ghidra, we find that there are 7 user devined functions: `main()`, `handle_client()`, `randGen()`, `displayCommands()`, `allowCopy()`, `kickOut()`, and `safety()`. The definitions of these functions are as follows:
