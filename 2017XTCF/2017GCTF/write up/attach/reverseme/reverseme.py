#-*- coding : utf-8 -*-

f = open('reverseMe','rb')
data = f.read()
size = f.tell()
f.close()
print data,len(data)
print size
i = 0

data = list(data)

while i<size/2:
	t = data[i]
	data[i] = data[size-1-i]
	data[size-1-i] = t
	i+=1

p = open('output','wb')

data = ''.join(data)
p.write(data)
p.close()
