def dec2bin(num):
    x = bin(num)[2:]
    if len(x)!=6:
        x = '0'*(6-len(x))+x
    return x

base64_list = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
with open("irc.txt","r")as f:
    data = f.read()
a=data.strip().split('\n\n')
cipher = ""
d = 0
for i in range(len(a)):
    temp = a[i]
    print temp
    if temp[-1]=="=" and temp[-2]=="=":
        padding_char = temp[-3]
        num = base64_list.find(padding_char)
        x = dec2bin(num)
        cipher += x[4:]
        d += 2
    elif temp[-1]=="=":
        padding_char = temp[-2]
        num = base64_list.find(padding_char)
        x = dec2bin(num)
        cipher += x[4:]
        d +=2
print cipher
print len(cipher)
