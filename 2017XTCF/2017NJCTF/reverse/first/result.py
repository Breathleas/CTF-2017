input = "juhuhfenlapsiuerhjifdunu"

check = "fee9f4e2f1faf4e4f0e7e4e5e3f2f5efe8fff6f4fdb4a5b2"

length =24
i = 0
v11 = 0
while(i!=length):
    v12 = ord(input[i])+i
    v11 = v11 ^ v12
    i = i+1

input = "juhuhfenlapsdunuhjifiuer"
check = check.decode("hex")
flag = ""
for i in range(0,24):
    temp = ord(input[i])^v11^ord(check[i])
    flag += chr(temp)
print flag
#goodjobyougetthisflag233
