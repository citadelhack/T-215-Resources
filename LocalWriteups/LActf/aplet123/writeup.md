# Given
In this challenge, we are given a C source file and a compiled binary. When reading through the binary, we see that there is a call to the unsecure gets() libc function.  
```


This looks to be an easy buffer overflow exploit.  However, before we get too excited, lets look at what security measures are in place.  To do this I use the checksec command, but this can be done using some other methods as well. When running checksec, I get the following output:
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
The stack is Non-Executable, so shellcode is not an option, but there is no PIE, so all internal functions have a static address. The only bump in the road is that there is a stack Canary
