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
