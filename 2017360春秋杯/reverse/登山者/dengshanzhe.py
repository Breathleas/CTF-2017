

global rand_base,rand_seed,rand_key
rand_base=0x3B9ACA07
rand_seed=0x01234567
rand_key=0x3B9ACA09

encodemap='EIFd6gwN42LR1vGrBYCnzHTStDqm+kxZpQVioj9O78es3UlAKhXcfybPM5W/0aJu'

def my_rand():
	global rand_base,rand_seed,rand_key
	i=(rand_base*rand_seed+rand_key)&0xffffffff
	j=((0xd6bfa181*i)/(2**32))&0xffffffff
	j=j/(2**23)
	j=(j*0x989677)&0xffffffff
	i=(i+2**32-j)&0xffffffff
	rand_seed=i
	return i

#print hex(my_rand())
ans=[]
path=[]
mmap=[]
for i in range(0,1014):
	ans.append([0 for i in range(1014)])
	path.append([0 for i in range(1014)])
	mmap.append([0 for i in range(1014)])
#mmap=[[0 for i in range(1014)]]*1014
for i in range(0,1014):
	for j in range(0,i+1):
		mmap[i][j]=my_rand()
		#print i,j,hex(mmap[0][0])

#print hex(mmap[0][0])

#for i in range(0,1014):
#	print hex(mmap[1013][i])

#ans=[[0 for i in range(1014)]]*1014
#path=[[0 for i in range(1014)]]*1014



for i in range(0,1014):
	ans[1013][i]=mmap[1013][i]

for i in range(1012,-1,-1):
	for j in range(0,i+1):
		if ans[i+1][j]<ans[i+1][j+1]:
			path[i][j]=1
			ans[i][j]=ans[i+1][j+1]+mmap[i][j]
		else:
			path[i][j]=0
			ans[i][j]=ans[i+1][j]+mmap[i][j]


f=[0]
flag=''
index=0
k=0

for i in range(0,169):
	for j in range(0,6):
		#print hex(mmap[i*6+j][index])
		k=k+mmap[i*6+j][index]
		f.append(path[i*6+j][index])
		index=path[i*6+j][index]+index
	#print ch

print f[5]
print hex(k)

for i in range(0,169):
	ch=0
	for j in range(0,6):
		ch=ch*2+f[i*6+j]
	flag=flag+encodemap[ch]


print hex(ans[0][0]),'aaaa'
print flag,"!!!!!!!!!!!!!!!!!"
print ''.join([str(f[i]) for i in range(1014)])