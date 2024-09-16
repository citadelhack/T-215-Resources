# Write-up
## Recon
In this challenge we are given a single unstripped binary. The results of `file` and `pwn checksec` are below:

File:
```
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a95ef3934257ab4cfc8764f78f355cab01faa9f6, for GNU/Linux 4.4.0, not stripped
```
pwn checksec:
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
