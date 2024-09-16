# Write-up
## Recon
In this challenge we are given a single unstripped binary. The results of `file` and `pwn checksec` are below:

File:
```
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a95ef3934257ab4cfc8764f78f355cab01faa9f6, for GNU/Linux 4.4.0, not stripped
```
pwn checksec:
```javascript
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
From this we can see that we are working with an x86-64 binary with most common midigations in effect, depending on the primatives available in the binary this could make exploitation difficult.

## Reversing
To find out what primatives we are working with we will now preform static analysis.

### Static Analysis
To do this we can throw the binary into ghidra and see what the decompiler spits out. The only user defined function in this binary is `main()`, defined as follows:
```C++
undefined8 main(void)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  allocator *paVar4;
  char *pcVar5;
  ulong uVar6;
  basic_ostream *pbVar7;
  long in_FS_OFFSET;
  int fd;
  int local_290;
  undefined8 local_288;
  undefined8 local_280;
  basic_string<> *local_278;
  undefined8 *local_270;
  basic_string buffer? [32];
  basic_string<> local_248 [535];
  allocator local_31;
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  std::__cxx11::basic_string<>::basic_string();
                    /* try { // try from 0010128b to 001012dc has its CatchHandler @ 001015c2 */
  std::operator<<((basic_ostream *)std::cout,"Tell me what you know about *nix philosophies: ");
  std::operator>>((basic_istream *)std::cin,buffer?);
  fd = 0;
  local_290 = 1;
  while( true ) {
    uVar6 = std::__cxx11::basic_string<>::size();
    if (uVar6 <= (ulong)(long)local_290) break;
    paVar4 = (allocator *)std::__cxx11::basic_string<>::operator[]((ulong)buffer?);
    local_31 = *paVar4;
    local_270 = &local_280;
                    /* try { // try from 0010131d to 00101321 has its CatchHandler @ 00101599 */
    std::__cxx11::basic_string<>::basic_string((initializer_list)local_248,&local_31);
    std::__new_allocator<char>::~__new_allocator((__new_allocator<char> *)&local_280);
    local_278 = local_248;
    local_288 = std::__cxx11::basic_string<>::begin();
    local_280 = std::__cxx11::basic_string<>::end();
    while( true ) {
      bVar1 = __gnu_cxx::operator!=((__normal_iterator *)&local_288,(__normal_iterator *)&local_280)
      ;
      if (!bVar1) break;
      pcVar5 = (char *)__gnu_cxx::__normal_iterator<>::operator*((__normal_iterator<> *)&local_288);
      fd = fd + *pcVar5;
      __gnu_cxx::__normal_iterator<>::operator++((__normal_iterator<> *)&local_288);
    }
    std::__cxx11::basic_string<>::~basic_string(local_248);
    local_290 = local_290 + 1;
  }
                    /* try { // try from 00101417 to 00101460 has its CatchHandler @ 001015c2 */
  read(fd + -0x643,buf,0x20);
  iVar3 = strcmp("make every program a filter\n",buf);
  if (iVar3 == 0) {
    std::basic_ifstream<>::basic_ifstream((char *)local_248,0x102055);
                    /* try { // try from 00101471 to 00101535 has its CatchHandler @ 001015ae */
    cVar2 = std::basic_ios<>::good();
    if (cVar2 == '\0') {
      pbVar7 = (basic_ostream *)
               std::basic_ostream<>::operator<<((basic_ostream<> *)std::cout,std::endl<>);
      pbVar7 = std::operator<<(pbVar7,"flag.txt: No such file or directory");
      std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar7,std::endl<>);
      pbVar7 = std::operator<<((basic_ostream *)std::cout,
                               "If you\'re running this locally, then running it on the remote serve r should give you the flag!"
                              );
      std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar7,std::endl<>);
    }
    else {
      pbVar7 = (basic_ostream *)
               std::basic_ostream<>::operator<<((basic_ostream<> *)std::cout,std::endl<>);
      pbVar7 = std::operator<<(pbVar7,"Welcome to pwning ^_^");
      std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar7,std::endl<>);
      system("/bin/cat flag.txt");
    }
    std::basic_ifstream<>::~basic_ifstream((basic_ifstream<> *)local_248);
  }
  else {
                    /* try { // try from 0010155b to 00101571 has its CatchHandler @ 001015c2 */
    pbVar7 = std::operator<<((basic_ostream *)std::cout,"You still lack knowledge about *nix sorry")
    ;
    std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar7,std::endl<>);
  }
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)buffer?);
  if (local_30 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
From this we can see that the program reads in a string from the user, does some operations on it, reads from a calculated file descriptor, compares the second read to a string, and prints the flag if the check passes. First let's find out what is done to our input string. The relevent code is as follows:
```C++
  std::operator<<((basic_ostream *)std::cout,"Tell me what you know about *nix philosophies: ");
  std::operator>>((basic_istream *)std::cin,buffer?);
  fd = 0;
  local_290 = 1;
  while( true ) {
    uVar6 = std::__cxx11::basic_string<>::size();
    if (uVar6 <= (ulong)(long)local_290) break;
    paVar4 = (allocator *)std::__cxx11::basic_string<>::operator[]((ulong)buffer?);
    local_31 = *paVar4;
    local_270 = &local_280;
                    /* try { // try from 0010131d to 00101321 has its CatchHandler @ 00101599 */
    std::__cxx11::basic_string<>::basic_string((initializer_list)local_248,&local_31);
    std::__new_allocator<char>::~__new_allocator((__new_allocator<char> *)&local_280);
    local_278 = local_248;
    local_288 = std::__cxx11::basic_string<>::begin();
    local_280 = std::__cxx11::basic_string<>::end();
    while( true ) {
      bVar1 = __gnu_cxx::operator!=((__normal_iterator *)&local_288,(__normal_iterator *)&local_280)
      ;
      if (!bVar1) break;
      pcVar5 = (char *)__gnu_cxx::__normal_iterator<>::operator*((__normal_iterator<> *)&local_288);
      fd = fd + *pcVar5;
      __gnu_cxx::__normal_iterator<>::operator++((__normal_iterator<> *)&local_288);
    }
    std::__cxx11::basic_string<>::~basic_string(local_248);
    local_290 = local_290 + 1;
  }
```
This can be pretty difficult to understand since it was origionally written in C++ so you will see artifacts from the operator overloading and object oriented features of C++, but what this code basically does is loop through the input string from index 1 to the end, adding the value of each character to the `int fd` variable.

The next relevent chunck of code (shortend for readability) is here:
```C++
  read(fd + -0x643,buf,0x20);
  iVar3 = strcmp("make every program a filter\n",buf);
  if (iVar3 == 0) {
      ...
      system("/bin/cat flag.txt");
  }
```
This reads from `fd - 0x643` and compares the result to `"make every program a filter\n`. If this check passes, the flag is printed. 
