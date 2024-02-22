# Write up
In this challenge, we are given a C source file and a compiled binary. When reading through the binary, we see that there is a function to print the flag:
```
void print_flag(void) {
  char flag[256];
  FILE *flag_file = fopen("flag.txt", "r");
  fgets(flag, sizeof flag, flag_file);
  puts(flag);
}
```
and a call to the unsecure gets() libc function:  
```
char input[64];
  puts("hello");
  while (1) {
    gets(input);
```

This looks to be an easy buffer overflow exploit.  However, before we get too excited, lets look at what security measures are in place.  To do this I use the checksec command, but this can be done using some other methods as well. When running checksec, I get the following output:
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
The stack is Non-Executable, so shellcode is not an option, but there is no PIE, so all internal functions have a static address. The only bump in the road is that there is a stack canary. 

A stack canary is a memory corruption mitigation implemented by most compilers to prevent overwriting a return address in the case of insecure code. It consists of a random value put on the stack which is checked before the function returns. If the value is not the same as it was when it was written, the program will crash and give a `*** Stack Smashing Detected ***` message.

There are two approaches to bypassing a stack canary.  The first is to attempt to brute force it, trying over and over again until you guess the canary correctly. However, this is very inefficient and luck-based (it doesn't make for a good ctf challenge).  The second approach is seeing if you can get the program to leak the canary from the stack, then since you know the value of the canary, you can overwrite it with itself while also overwriting the return address of the function, passing the canary check.

When looking for a leak, we generally look for a print statement that takes a char* as an argument, so something like `printf(buffer)` or `print("%s", buffer)`, and then see if we can control the location of the buffer variable. The source code has the following print statement:
```
char *s = strstr(input, "i'm");
    if (s) {
      printf("hi %s, i'm aplet123\n", s + 4);
```
The buffer we need to control is `s + 4`. This buffer is created by the `strstr(char* buffer, char* key)` function. This function looks through the buffer for the first instance of the key substring, and returns that address. the substring length is 3, but 4 is added to the address, this is most likely to bypass the assumed space. However, if we write "i'm" to the end of the buffer, we can use this to bypass the null terminator, causing an unintended read from stack space, and since `gets()` is used, we can overflow the buffer to write "i'm" to any point below the buffer in the stack to read any part of it. All we need to do is find the location of the stack canary.

To do this, I use gdb, a dynamic and static binary analysis tool. first I run `gdb aplet123` to start gdb with the binary loaded, I then use the command `info func` to look at the function symbols gdb was able to resolve. Since this binary was not stripped, we find all the user-defined functions and their corresponding addresses in the output:
```
(gdb) info func
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401030  puts@plt
0x0000000000401040  __stack_chk_fail@plt
0x0000000000401050  setbuf@plt
0x0000000000401060  printf@plt
0x0000000000401070  srand@plt
0x0000000000401080  fgets@plt
0x0000000000401090  strcmp@plt
0x00000000004010a0  time@plt
0x00000000004010b0  gets@plt
0x00000000004010c0  fopen@plt
0x00000000004010d0  sleep@plt
0x00000000004010e0  strstr@plt
0x00000000004010f0  rand@plt
0x0000000000401100  _start
0x0000000000401130  _dl_relocate_static_pie
0x0000000000401140  deregister_tm_clones
0x0000000000401170  register_tm_clones
0x00000000004011b0  __do_global_dtors_aux
0x00000000004011e0  frame_dummy
0x00000000004011e6  print_flag
0x0000000000401261  main
0x00000000004013d8  _fini
```
Print_flag is the address we will want to jump to, so we save this for later. However, the function we will be exploiting is main so I run `disass main` to get the disassembly of the function.  The output is as follows:
```
(gdb) disass main
Dump of assembler code for function main:
   0x0000000000401261 <+0>:     push   %rbp
   0x0000000000401262 <+1>:     mov    %rsp,%rbp
   0x0000000000401265 <+4>:     sub    $0x60,%rsp
   0x0000000000401269 <+8>:     mov    %fs:0x28,%rax
   0x0000000000401272 <+17>:    mov    %rax,-0x8(%rbp)
   0x0000000000401276 <+21>:    xor    %eax,%eax
   0x0000000000401278 <+23>:    mov    0x2df9(%rip),%rax        # 0x404078 <stdout@GLIBC_2.2.5>
   0x000000000040127f <+30>:    mov    $0x0,%esi
   0x0000000000401284 <+35>:    mov    %rax,%rdi
   0x0000000000401287 <+38>:    call   0x401050 <setbuf@plt>
   0x000000000040128c <+43>:    mov    $0x0,%edi
   0x0000000000401291 <+48>:    call   0x4010a0 <time@plt>
   0x0000000000401296 <+53>:    mov    %eax,%edi
   0x0000000000401298 <+55>:    call   0x401070 <srand@plt>
   0x000000000040129d <+60>:    lea    0xe5f(%rip),%rax        # 0x402103
   0x00000000004012a4 <+67>:    mov    %rax,%rdi
   0x00000000004012a7 <+70>:    call   0x401030 <puts@plt>
   0x00000000004012ac <+75>:    lea    -0x50(%rbp),%rax
   0x00000000004012b0 <+79>:    mov    %rax,%rdi
   0x00000000004012b3 <+82>:    call   0x4010b0 <gets@plt>
   0x00000000004012b8 <+87>:    lea    -0x50(%rbp),%rax
   0x00000000004012bc <+91>:    lea    0xe46(%rip),%rdx        # 0x402109
   0x00000000004012c3 <+98>:    mov    %rdx,%rsi
   0x00000000004012c6 <+101>:   mov    %rax,%rdi
   0x00000000004012c9 <+104>:   call   0x4010e0 <strstr@plt>
   0x00000000004012ce <+109>:   mov    %rax,-0x58(%rbp)
   0x00000000004012d2 <+113>:   cmpq   $0x0,-0x58(%rbp)
   0x00000000004012d7 <+118>:   je     0x4012fa <main+153>
   0x00000000004012d9 <+120>:   mov    -0x58(%rbp),%rax
   0x00000000004012dd <+124>:   add    $0x4,%rax
   0x00000000004012e1 <+128>:   mov    %rax,%rsi
   0x00000000004012e4 <+131>:   lea    0xe22(%rip),%rax        # 0x40210d
   0x00000000004012eb <+138>:   mov    %rax,%rdi
   0x00000000004012ee <+141>:   mov    $0x0,%eax
   0x00000000004012f3 <+146>:   call   0x401060 <printf@plt>
   0x00000000004012f8 <+151>:   jmp    0x4012ac <main+75>
   0x00000000004012fa <+153>:   lea    -0x50(%rbp),%rax
   0x00000000004012fe <+157>:   lea    0xe1d(%rip),%rdx        # 0x402122
   0x0000000000401305 <+164>:   mov    %rdx,%rsi
   0x0000000000401308 <+167>:   mov    %rax,%rdi
   0x000000000040130b <+170>:   call   0x401090 <strcmp@plt>
   0x0000000000401310 <+175>:   test   %eax,%eax
   0x0000000000401312 <+177>:   jne    0x401341 <main+224>
   0x0000000000401314 <+179>:   lea    0xe1f(%rip),%rax        # 0x40213a
   0x000000000040131b <+186>:   mov    %rax,%rdi
   0x000000000040131e <+189>:   call   0x401030 <puts@plt>
   0x0000000000401323 <+194>:   mov    $0x5,%edi
   0x0000000000401328 <+199>:   call   0x4010d0 <sleep@plt>
   0x000000000040132d <+204>:   lea    0xe17(%rip),%rax        # 0x40214b
   0x0000000000401334 <+211>:   mov    %rax,%rdi
   0x0000000000401337 <+214>:   call   0x401030 <puts@plt>
   0x000000000040133c <+219>:   jmp    0x4012ac <main+75>
   0x0000000000401341 <+224>:   lea    -0x50(%rbp),%rax
   0x0000000000401345 <+228>:   lea    0xe02(%rip),%rdx        # 0x40214e
   0x000000000040134c <+235>:   mov    %rdx,%rsi
   0x000000000040134f <+238>:   mov    %rax,%rdi
   0x0000000000401352 <+241>:   call   0x401090 <strcmp@plt>
   0x0000000000401357 <+246>:   test   %eax,%eax
   0x0000000000401359 <+248>:   jne    0x401381 <main+288>
   0x000000000040135b <+250>:   lea    0xdec(%rip),%rax        # 0x40214e
   0x0000000000401362 <+257>:   mov    %rax,%rdi
   0x0000000000401365 <+260>:   call   0x401030 <puts@plt>
   0x000000000040136a <+265>:   nop
   0x000000000040136b <+266>:   mov    $0x0,%eax
   0x0000000000401370 <+271>:   mov    -0x8(%rbp),%rdx
   0x0000000000401374 <+275>:   sub    %fs:0x28,%rdx
   0x000000000040137d <+284>:   je     0x4013d4 <main+371>
   0x000000000040137f <+286>:   jmp    0x4013cf <main+366>
   0x0000000000401381 <+288>:   call   0x4010f0 <rand@plt>
   0x0000000000401386 <+293>:   movslq %eax,%rcx
   0x0000000000401389 <+296>:   movabs $0xf83e0f83e0f83e1,%rdx
   0x0000000000401393 <+306>:   mov    %rcx,%rax
   0x0000000000401396 <+309>:   mul    %rdx
   0x0000000000401399 <+312>:   mov    %rdx,%rax
   0x000000000040139c <+315>:   shr    %rax
   0x000000000040139f <+318>:   mov    %rax,%rdx
   0x00000000004013a2 <+321>:   shl    $0x5,%rdx
   0x00000000004013a6 <+325>:   add    %rax,%rdx
   0x00000000004013a9 <+328>:   mov    %rcx,%rax
   0x00000000004013ac <+331>:   sub    %rdx,%rax
   0x00000000004013af <+334>:   lea    0x0(,%rax,8),%rdx
   0x00000000004013b7 <+342>:   lea    0x2942(%rip),%rax        # 0x403d00 <responses>
   0x00000000004013be <+349>:   mov    (%rdx,%rax,1),%rax
   0x00000000004013c2 <+353>:   mov    %rax,%rdi
   0x00000000004013c5 <+356>:   call   0x401030 <puts@plt>
   0x00000000004013ca <+361>:   jmp    0x4012ac <main+75>
   0x00000000004013cf <+366>:   call   0x401040 <__stack_chk_fail@plt>
   0x00000000004013d4 <+371>:   leave
   0x00000000004013d5 <+372>:   ret
   End of assembler dump.
```
What we are looking for is the offset of the beginning of the buffer to the return address. To do this we want to look for where the buffer is referenced. Since we have the source code, we know the buffer is first referenced in the `gets()` call, so lets take a look at the disassembly of that call and its setup:
```
   0x00000000004012ac <+75>:    lea    -0x50(%rbp),%rax
   0x00000000004012b0 <+79>:    mov    %rax,%rdi
   0x00000000004012b3 <+82>:    call   0x4010b0 <gets@plt>
```
We see that the address of rbp - 0x50 is loaded into the rax register. The value of the rax register is then moved into the rdi register, which is the register that holds first function argument in the Linux calling convention. Since `gets()` only takes one argument, we know that this is the address of the beginning of the buffer, and since rbp points to the saved base pointer, we just add 8 (the size of this pointer in bytes) 0x50 and we have the offset to the return address.  The next thing we want to find is the offset to the stack canary. There are two ways to do this. One way is to run the program and look at the stack to find the value and count the bytes to the beginning of the buffer. However, if we know what we are looking for, we can find where it is initialized in the assembly and get the offset without counting. The assembly we are looking for is as follows:
```
   0x0000000000401269 <+8>:     mov    %fs:0x28,%rax
   0x0000000000401272 <+17>:    mov    %rax,-0x8(%rbp)
```
From this, we see that the canary value is placed on the stack at rbp - 8 which gives an offset of 0x48, or 72 bytes from the beginning of the buffer. However, just to be safe, let's check the value on the stack to make sure there are no surprises. To do this we are going to set a break point at the call the `gets()` and run the program. To do this we will first run the command `break *0x00000000004012b3` and then `run`. When the break point is reached we are going to look at the stack memory starting at the buffer and going to the return address using the command `x/24x $rbp-0x50`.  When we do this we get the following output:
```
(gdb) x/24x $rbp-0x50
0x7fffffffdbd0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdbe0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdbf0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdc00: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdc10: 0x00000000      0x00000000      0x976db300      0x2e6aab87
0x7fffffffdc20: 0x00000001      0x00000000      0xf7df26ca      0x00007fff
```
From this output we see the stack canary is `0x976db300 0x2e6aab87`. But this is representing the value as two big endian dwords. Let's convert it into how it is represented in memory. one little endian qword, `0x003bd67978baa6e2`. We see we have an 8 byte stack canary. If you redo the last few steps to re-run the program multiple times, you will see the value is randomized each time, but there is one constant, the first byte is always `0x00`. This means that when we try and leak the value, if we give `printf()` a pointer at an offset of 0x48, we will get no leak, since it will stop reading at the null byte. To get the leak we just need to increase the offset by one to ensure that `printf()` leaks the whole canary. 

With this information we now have everything we need to write and exploit to leak the canary, and then overwrite the return address and print the flag. The python script I wrote to do this can be found in this directory under the name `apletsolve.py`.
