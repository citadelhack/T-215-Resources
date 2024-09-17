from pwn import *

context.log_level = 'debug'
p = process("./chal")
#p = remote("nix.ctf.csaw.io", 1000)

p.sendlineafter(b"phies: ", b"A" + b"B"*23 + b"U")
p.sendline(b"make every program a filter")

print(p.clean())
