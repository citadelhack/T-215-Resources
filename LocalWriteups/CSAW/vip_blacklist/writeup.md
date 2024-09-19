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

**main():**
```C
undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  fflush(stdout);
  handle_client();
  return 0;
}
```

**handle_client():**
```C
void handle_client(void)

{
  long lVar1;
  bool bVar2;
  int iVar3;
  size_t sVar4;
  char *pcVar5;
  long in_FS_OFFSET;
  uint remaining_commands;
  uint local_a4;
  char *rand_str;
  char *local_98;
  FILE *local_90;
  char local_82 [10];
  char command [32];
  char local_58 [64];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  remaining_commands = 0x14;
  randGen(&rand_str);
  puts(
      "\"Welcome to the club. It\'s ok, don\'t be in a rush. You\'ve got all the time in the world. As long as you are a vip that is.\""
      );
  displayCommands();
LAB_00101c2e:
  do {
    pcVar5 = fgets(command,0x20,stdin);
    if (pcVar5 == (char *)0x0) {
code_r0x00101c50:
      if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    sVar4 = strcspn(command,"\n");
    command[sVar4] = '\0';
    iVar3 = strcmp(command,"exit");
    if (iVar3 == 0) {
      puts("Bye!");
      goto code_r0x00101c50;
    }
    iVar3 = strcmp(command,rand_str);
    if (iVar3 == 0) {
      iVar3 = strcmp(whitelist,"queue");
      if (iVar3 != 0) {
        puts("\nAh VIP, please come this way...");
        allowCopy();
      }
    }
    sprintf(local_82,command);
    local_58[0] = 'E';
    local_58[1] = 'x';
    local_58[2] = 'e';
    local_58[3] = 'c';
    local_58[4] = 'u';
    local_58[5] = 't';
    local_58[6] = 'i';
    local_58[7] = 'n';
    local_58[8] = 'g';
    local_58[9] = ':';
    local_58[10] = ' ';
    local_58[0xb] = '\0';
    local_58[0xc] = '\0';
    local_58[0xd] = '\0';
    local_58[0xe] = '\0';
    local_58[0xf] = '\0';
    local_58[0x10] = '\0';
    local_58[0x11] = '\0';
    local_58[0x12] = '\0';
    local_58[0x13] = '\0';
    local_58[0x14] = '\0';
    local_58[0x15] = '\0';
    local_58[0x16] = '\0';
    local_58[0x17] = '\0';
    local_58[0x18] = '\0';
    local_58[0x19] = '\0';
    local_58[0x1a] = '\0';
    local_58[0x1b] = '\0';
    local_58[0x1c] = '\0';
    local_58[0x1d] = '\0';
    local_58[0x1e] = '\0';
    local_58[0x1f] = '\0';
    local_58[0x20] = '\0';
    local_58[0x21] = '\0';
    local_58[0x22] = '\0';
    local_58[0x23] = '\0';
    local_58[0x24] = '\0';
    local_58[0x25] = '\0';
    local_58[0x26] = '\0';
    local_58[0x27] = '\0';
    local_58[0x28] = '\0';
    local_58[0x29] = '\0';
    local_58[0x2a] = '\0';
    local_58[0x2b] = '\0';
    local_58[0x2c] = '\0';
    local_58[0x2d] = '\0';
    local_58[0x2e] = '\0';
    local_58[0x2f] = '\0';
    local_58[0x30] = '\0';
    local_58[0x31] = '\0';
    local_58[0x32] = '\0';
    local_58[0x33] = '\0';
    local_58[0x34] = '\0';
    local_58[0x35] = '\0';
    local_58[0x36] = '\0';
    local_58[0x37] = '\0';
    local_58[0x38] = '\0';
    local_58[0x39] = '\0';
    local_58[0x3a] = '\0';
    local_58[0x3b] = '\0';
    local_58[0x3c] = '\0';
    local_58[0x3d] = '\0';
    local_58[0x3e] = '\0';
    local_58[0x3f] = '\0';
    strcat(local_58,local_82);
    sVar4 = strlen(local_58);
    *(undefined4 *)(local_58 + sVar4) = 0xa2e2e2e;
    local_58[sVar4 + 4] = '\0';
    puts(local_58);
    bVar2 = false;
    for (local_a4 = 0; local_a4 < 4; local_a4 = local_a4 + 1) {
      iVar3 = strcmp(command,whitelist + (long)(int)local_a4 * 6);
      if (iVar3 == 0) {
        bVar2 = true;
        break;
      }
    }
    if (bVar2) {
      iVar3 = strcmp(command,"queue");
      if (iVar3 == 0) {
        printf("You are currently in position: %d\n",(ulong)remaining_commands);
        goto LAB_00101c2e;
      }
      local_90 = popen(command,"r");
      if (local_90 == (FILE *)0x0) {
        perror("Error executing command");
        goto code_r0x00101c50;
      }
      while( true ) {
        pcVar5 = fgets(command,0x20,local_90);
        if (pcVar5 == (char *)0x0) break;
        printf("%s",command);
      }
      pclose(local_90);
      remaining_commands = remaining_commands - 1;
      if (remaining_commands == 0) {
        puts("Hello! You are at the front of the queue now. Oh hold on one second");
        puts("I\'m getting some new info...");
        kickOut();
      }
    }
    else {
      local_98 = "Command not allowed\n";
      printf("%s","Command not allowed\n");
    }
    displayCommands();
  } while( true );
}
```

**randGen():**
```C
void randGen(void **param_1)

{
  int iVar1;
  void *pvVar2;
  time_t tVar3;
  ulong local_18;
  
  pvVar2 = malloc(10);
  tVar3 = time((time_t *)0x0);
  srand((uint)tVar3);
  for (local_18 = 0; local_18 < 10; local_18 = local_18 + 1) {
    iVar1 = rand();
    *(char *)(local_18 + (long)pvVar2) = (char)iVar1;
  }
  *param_1 = pvVar2;
  return;
}
```

**displayCommands():**
```C
void displayCommands(void)

{
  uint local_c;
  
  printf("\nCommands: ");
  for (local_c = 0; local_c < 4; local_c = local_c + 1) {
    printf("%s ",whitelist + (long)(int)local_c * 6);
  }
  putchar(10);
  return;
}
```

**allowCopy():**
```C
void allowCopy(void)

{
  int iVar1;
  ssize_t sVar2;
  size_t sVar3;
  long in_FS_OFFSET;
  int i;
  int local_8c;
  int local_88;
  ulong local_80;
  char safety_var [16];
  char new_command [40];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  puts(
      "You may add a new command, \"queue\", to your possible commands which will give you your posi tion. \nIf you would not like this, just press enter."
      );
  displayCommands();
  sVar2 = read(0,new_command,0x20);
  if (sVar2 < 0) {
    perror("Error reading from stdin");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  sVar3 = strcspn(new_command,"\n");
  new_command[sVar3] = '\0';
  i = 0;
  while( true ) {
    sVar3 = strlen("queue");
    if (sVar3 + 1 <= (ulong)(long)i) break;
    if (new_command[i] != "queue"[i]) {
      kickOut();
    }
    i = i + 1;
  }
  puts(
      "\"We are currently getting you a valet to inform you of your queue position\nPlease wait one second...\""
      );
  safety_var[6] = 'e';
  safety_var[7] = 'x';
  safety_var[8] = 'i';
  safety_var[9] = 't';
  safety_var[0] = 'c';
  safety_var[1] = 'l';
  safety_var[2] = 'e';
  safety_var[3] = 'a';
  safety_var[4] = 'r';
  safety_var[5] = '\0';
  safety_var[10] = '\0';
  safety_var[0xb] = '\0';
  safety_var[0xc] = 'l';
  safety_var[0xd] = 's';
  safety_var[0xe] = '\0';
  safety_var[0xf] = '\0';
  for (local_8c = 3; -1 < local_8c; local_8c = local_8c + -1) {
    strcpy(whitelist + (long)local_8c * 6,whitelist + (long)(local_8c + -1) * 6);
  }
  for (local_88 = 0; (long)local_88 < sVar2 + -1; local_88 = local_88 + 1) {
    whitelist[local_88] = new_command[local_88];
  }
  iVar1 = safety(safety_var);
  if (iVar1 == 0) {
    kickOut();
  }
  else {
    sleep(1);
    puts("\"The valet has arrived, feel free to check your queue position now.\"");
  }
  for (local_80 = 0; local_80 < 4; local_80 = local_80 + 1) {
    puts(whitelist + local_80 * 6);
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

**kickOut():**
```C
void kickOut(void)

{
  puts("\"You are not a real VIP. Follow this person out.\"");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

**safety():**
```C
int safety(char *param_1)

{
  int iVar1;
  ulong one;
  size_t sVar2;
  ulong four;
  ulong local_18;
  
  iVar1 = strcmp(whitelist,"queue");
  one = (ulong)(iVar1 == 0);
  for (four = one; four < 4; four = four + 1) {
    sVar2 = strlen(whitelist + four * 6);
    if (5 < sVar2) {
      kickOut();
    }
    local_18 = 0;
    while( true ) {
      sVar2 = strlen(param_1 + (four - one) * 6);
      if (sVar2 <= local_18) break;
      if (param_1[local_18 + (four - one) * 6] != whitelist[local_18 + four * 6]) {
        kickOut();
      }
      local_18 = local_18 + 1;
    }
  }
  return 1;
}
```
First we see that `main()` just sets buffer modes and calls `handle_client()`. In `handle_client()` we see that it takes in input, and then preforms some checks on your input, and depending on what checks your input passes or doesnt pass, the code will preform some action. We can also see that `randGen()` is called, which generates a random string of 10 bytes. If the input is a string contained in the `whitelist` array in `.data`, `popen()` is called and the command is executed, otherwise we are told that our command is not allowed. If the input is equal to the random string, `allowCopy()` is called. This function will allow us to add a new command. It intends for this new command to be the internal command queue. After we input our new command, the first 5 bytes are checked to make sure they are the string `"queue"`. After this a check buffer is set up and the `safety()` function is called. This function preforms some some checks on the `whitelist` array calls `kickOut()` which exits the program if the checks fail. 

## The Vulnerabilities
The first vulnerability you may see is a format string vuln in the call `sprintf(local_82,command);`. Because of the midigations in effect, this cannot be used to directly overwrite any function pointers, but it can be used to leak values (the random string in particular). However, I did not use this vulnerablilty in my solution. In order to find the value of the random string, I used the same random function seeded with the current time, just like in the `genRand()`, in order to calculate the value client side.

The vulnerabilities that I exploited exist in the `allowCopy()` and `safety()`. The first vulnerability is that the `read()` call allows us to read 0x20 bytes when only 0x6 should be required, and only the first 5 bytes are checked to be equal to `queue`. Furthermore, when the new command is copied into the `whitelist`, the length of the read is used instead of the size of `queue`. This allows us to overwrite the entirety of the `whitelist` buffer. Furthermore, the read call will read until the `0xa` byte (newline), is recieved. This means we can read in null bytes. Because of this we can add our own command as long as the first 5 bytes are `queue`. However, there are still checks we must pass in the `safety()` function. The first thing to notice about the `safety()` function is the parameter it is passed, which is a `char*` to the an array defined in `allowCopy()`.

```C
  safety_var[6] = 'e';
  safety_var[7] = 'x';
  safety_var[8] = 'i';
  safety_var[9] = 't';
  safety_var[0] = 'c';
  safety_var[1] = 'l';
  safety_var[2] = 'e';
  safety_var[3] = 'a';
  safety_var[4] = 'r';
  safety_var[5] = '\0';
  safety_var[10] = '\0';
  safety_var[0xb] = '\0';
  safety_var[0xc] = 'l';
  safety_var[0xd] = 's';
  safety_var[0xe] = '\0';
  safety_var[0xf] = '\0';
```
This can be simplified to `"clear\0exit\0\0ls\0\0"`. Then in `safety()`, the following checks are run:

```C
iVar1 = strcmp(whitelist,"queue");
  one = (ulong)(iVar1 == 0);
  for (four = one; four < 4; four = four + 1) {
    sVar2 = strlen(whitelist + four * 6);
    if (5 < sVar2) {
      kickOut();
    }
    local_18 = 0;
    while( true ) {
      sVar2 = strlen(param_1 + (four - one) * 6);
      if (sVar2 <= local_18) break;
      if (param_1[local_18 + (four - one) * 6] != whitelist[local_18 + four * 6]) {
        kickOut();
      }
      local_18 = local_18 + 1;
    }
  }
```
This chunk of code first checks whether the first stirng in `whitelist` is `queue`, if it is, the following loop starts at the second string in `whitelist` and if not it starts at the first. Then it loops through each command in the `whitelist` and checks that the string in `whitelist` has a length of less than or equal to 5 and then checks strings stored there against the corresponding string in the `safety_var`. If these checks fails at any point, `kickOut()` is called. However, the check uses the string length of the correct string in when comparing the strings. This means that I can append a command to a correct command as long as the total string length is less than or equal to 5. The best canditate for this is `ls`, since it is the smallest. However, after modifying it to `ls;` to append another command, we only have 2 characters to work with. This seems difficult to overcome until we remember that the normal program that we run to get a shell is `/bin/sh`. This is 7 characters but the name of the file without the path is just `sh`, 2 letters. And we know from either reading documentation or deduction from the fact that `ls`, `clear`, and `exit` run fine, that `popen()` uses the `$PATH` environment variable to find binaries. Since `/bin` is in `$PATH` by default on linux, we can simple make the `ls` command in the `whitelist` into `ls;sh` to pass the checks and gain a shell.

My solution code and the origional binary are in this directory if you want to try for yourself.

