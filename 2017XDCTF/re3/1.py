import string
a="rlmlphghFEYKGFGF"
data = []
for i in range(0,8):
    data.append(ord(a[i])-97)
    data.append(ord(a[i+8])-65)
print data
zidian = string.lowercase + string.digits
print zidian
test = []
for i in range(16):
    temp = []
    if(i%2==1):
        for j in zidian:
            if(ord(j)^0xFE)%25==data[i]:
                temp.append(j)
    if(i%2==0):
        for j in zidian:
            if(ord(j)^0xE0)%25==data[i]:
                temp.append(j)
    print temp
    test.append(temp)


#n33d4k3y70d3c0d3

'''
def digui(a,depth,now):
    if depth==9:
        for i in a[depth]:
            print now+i
    else:
        for i in a[depth]:
            digui(a,depth+1,now+i)

digui(test,0,"")
'''
a="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
print len(a)
a = "http://email.163.com"
print len(a)
b = [1,3,64,30,13,86,31,16,31,17,93,89,27,70,6,65,74]
data = ""
for i in range(17):
    temp = ord(a[i])^b[i]
    data += chr(temp)
print data
#flag{n33d4k3y70d3c0d3iw4n7y0urp455w0rd}