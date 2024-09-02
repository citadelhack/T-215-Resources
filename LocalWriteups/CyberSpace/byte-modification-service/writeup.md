# Write-up
## Recon
In this challenge I was given a single unstripped binary. The results of `file` and `pwn checksec` are below:

File:
```
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f041a6eba0e7557961bb783a363f0cb0bbb3eb8b, for GNU/Linux 3.2.0, not stripped
```

Pwn Checksec:
```javascript
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

From this I saw that I was working with an unstripped x86-64 bit binary with NX and a Stack Canary but no PIE, this should make reversing and exploit crafting relatively simple.

## Reversing
Next to reverse the binary and see what primitives we are dealing with.

### Static Analysis
For static analysis, my go-to tool is ghidra. So I load it into ghidra and look at the functions it finds. 

![Fig 1.](./funcs.png "Ghidra function symbol tree")

From this I can see that there are 4 user defined functions, `main()`, `init()`, `vuln()`, and `win()`. These functions are decompiled as follows (some changes have been made for correctness and readability):

**main():**

```C
int main()

{
  init();
  vuln();
  return 0;
}
```

**init():**

```C
void init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  
  syscall();
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  iVar1 = setvbuf(stderr,(char *)0x0,2,0);
  return;
}
```

**vuln():**

```C
void vuln(void)

{
  long in_FS_OFFSET;
  undefined8 uStack_58;
  byte local_4c [4];
  uint local_48;
  uint local_44;
  undefined8 local_40;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_40 = 0;
  puts("which stack position do you want to use?");
  __isoc99_scanf("%d",&local_44);
  local_44 = local_44 << 3;
  local_40 = *(undefined8 *)((long)&uStack_58 + (ulong)local_44);
  puts("you have one chance to modify a byte by xor.");
  puts("Byte Index?");
  __isoc99_scanf("%d",&local_48);
  if (((int)local_48 < 0) || (7 < (int)local_48)) {
    puts("don\'t cheat!");
    exit(0);
  }
  puts("xor with?");
  __isoc99_scanf("%d",local_4c);
  local_38[(ulong)local_48 - 8] = local_38[(ulong)local_48 - 8] ^ local_4c[0];
  puts("finally, do you have any feedback? it will surely help us improve our service.");
  __isoc99_scanf("%20[^@]",local_38);
  printf(local_38);
  bye();
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

**win():**

```C
void win(void)

{
  FILE *__stream;
  long in_FS_OFFSET;
  char local_48 [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __stream = fopen("flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("flag.txt not found!");
    exit(0);
  }
  fgets(local_48,0x32,__stream);
  puts(local_48);
  puts("How could you do that?!");
  puts("That\'s my precious secret.");
  puts("Anyway congratulations");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

From this decomilation we can see that `main()` calls `init()` which sets up the buffer modes for `stdin`, `stdout`, and `stderr`, this is not very important for our purposes. Then main calls `vuln()`, which allows us to do some funny buisness with the stack and then gives us a format string vulnerability at the line `printf(local_38);`. After this the `bye()` funciton is called which prints a message and exits the program.

```python
[+] Opening connection to byte-modification-service.challs.csc.tf on port 1337: Done
b'== proof-of-work: disabled ==\nwhich stack position do you want to use?\n'
b'you have one chance to modify a byte by xor.\nByte Index?\n'
b'xor with?\n'
b'finally, do you have any feedback? it will surely help us improve our service.\n'
b"\n                                                                                                                                                                                                                                                      4AAAAAAAACSCTF{y0u_Kn0W_fOrmA7_57r1NG_4nd_C4LL_BYTE5}\nHow could you do that?!\nThat's my precious secret.\nAnyway congratulations\n"
[*] Closed connection to byte-modification-service.challs.csc.tf port 1337
```
