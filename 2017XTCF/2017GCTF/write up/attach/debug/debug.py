import hashlib

def change(a,b):
	s = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113]
	return s[a]^b

def flag(a):
	m = hashlib.md5()

	m.update(a)
	s = m.hexdigest().upper()
	print 'flag{'+s+'}'

def convert(A0):
	A2 = ''
	num = 0
	while num < len(A0):
		c = A0[num]
		num2 = 1
		while num2 < 15:
			c = chr(change(num2,ord(c)))
			num2 += 1
		A2 += c
		num += 1
	print A2
	return flag(A2)

print convert('CreateByTenshine')
