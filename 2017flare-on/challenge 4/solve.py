import os
root = "./flareon2016challenge"
data = []
for i in os.listdir(root):
    path = os.path.join(root,i)
    print path
    data.append(path)
xor = ""
for i in range(len(data)):
    with open(data[i],'rb')as f:
        temp = f.read()[0x400+i*0x10:0x408+i*0x10]
        xor += temp
origin = [55, 231, 216, 190, 122, 83, 48, 37, 187, 56, 87, 38, 151, 38, 111, 80, 244, 117, 103, 191, 176, 239, 165, 122, 101, 174, 171, 102, 115, 160, 163, 161]

flag = ""
for i in range(32):
    temp = origin[i]^(ord(xor[i]))
    flag += chr(temp)
print flag
#bl457_fr0m_th3_p457@flare-on.com