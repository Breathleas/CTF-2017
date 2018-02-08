import struct
from z3 import *

f = open('./cp','rb')

def read_int():
	return struct.unpack('Q', f.read(8))[0]

mem_size = read_int()
print 'mem:', hex(mem_size)
code_size = read_int()
print 'code:', hex(code_size)


op_code = ['XXXXXXXXXXXXXXX', 'AND', 'OR', 'XOR', 'IF']

s = Solver()
s.add(BitVec('0',1) == 0)
s.add(BitVec('1',1) == 1)

for i in range(code_size):
	op = read_int()
	src1 = BitVec(str(read_int()),1)
	src2 = BitVec(str(read_int()),1)
	src3 = BitVec(str(read_int()),1)
	dst = BitVec(str(read_int()),1)
	#print '%s: %s %#x %#x %#x -> %#x'% (i, op_code[op], src1, src2, src3, dst) 

	if op_code[op] == 'AND':
		s.add(dst == src1 & src2 )
	elif op_code[op] == 'OR':
		s.add(dst == src1 | src2 )
	elif op_code[op] == 'XOR':
		s.add(dst == src1 ^ src2 )
	elif op_code[op] == 'IF':
		s.add(dst == (src1 & src2) | ((~src1) & src3))
	else:
		print "Unknown OP"

s.add(BitVec(str(0x87e8),1)==1)
print 'checking...'
print(s.check())
m = s.model()
print(s.model())

'''
XOR 0x219b 0x219a 0xffffffffffffffff -> 0x219c
AND 0x1f9c 0x1fe1 0xffffffffffffffff -> 0x219d
OR 0x219d 0x219e 0xffffffffffffffff -> 0x21a0
IF 0x5a 0x0 0x0 -> 0x21a2
'''

buf = ''
for i in range(0x87e9,0x8828+1):
	buf += str(m[BitVec(str(i), 1)].as_long())

print ('%x'%int(buf[::-1],2)).decode('hex')[::-1]

buf = ''
for i in range(2,0x112):
	buf += str(m[BitVec(str(i), 1)].as_long())

print ('%x'%int(buf[::-1],2)).decode('hex')[::-1]
