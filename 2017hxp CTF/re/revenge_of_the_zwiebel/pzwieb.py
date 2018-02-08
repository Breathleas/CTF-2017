from pwn import *

ans = list('\xff'*60)

#ans = ['\x00', '\x00', '\x00', '\x01', ' ', '\x00', '\x04', ' ', ' ', '\x00', '\x00', '\x00', '\x08', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00']
#6bfc77ff7fff35efb37ceddfff3fff7feffb3ff7fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

path = []

p = process(['/home/echo/pin-3.5/pin','-t','/home/echo/pin-3.5/source/tools/ManualExamples/obj-intel64/inscount0.so', '--', '/home/echo/Desktop/zwieb'])	# -t /home/echo/pin-3.5/source/tools/ManualExamples/obj-intel64/inscount0.so -- ./zwieb

print p.recv()

p.sendline(''.join(ans))
a = p.recv().split()[1]
print a
p.close()
last = int(a)



for i in range(480):
	tmp = ans[:]
	for j in range(480):
		try:
			path.index(j)
			continue
		except:
			tmp[j/8] = chr(ord(tmp[j/8])^(1<<(j%8)))
			p = process(['/home/echo/pin-3.5/pin','-t','/home/echo/pin-3.5/source/tools/ManualExamples/obj-intel64/inscount0.so', '--', '/home/echo/Desktop/zwieb'])	# -t /home/echo/pin-3.5/source/tools/ManualExamples/obj-intel64/inscount0.so -- ./zwieb

			p.recv()

			p.sendline(''.join(tmp))
			print ''.join(tmp).encode('hex')
			a = int(p.recv().split()[1])
			print i,j,a
			p.close()
			if a-last > 100:
				last = a
				ans[j/8] = chr( ord(ans[j/8]) ^ (1<<(j%8)) )
				path.append(j)
				print (''.join(ans)).encode('hex'),ans
				break
			if a-last < 1000:
				tmp[j/8] = chr(ord(tmp[j/8])^(1<<(j%8)))

	if j == 479:
		break
print ans
