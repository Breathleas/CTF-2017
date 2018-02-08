import hashlib
check="4746bbbd02bb590fbeac2821ece8fc5cad749265ca7503ef4386b38fc12c4227b03ecc45a7ec2da7be3c5ffe121734e8"
for i in range(48,122):
    for j in range(48,122):
        for m in range(48,122):
            for n in range(48,122):
                temp = chr(i)+chr(j)+chr(m)+chr(n)
                hashvalue = hashlib.md5(temp).hexdigest()
                if hashvalue[0:16] == check[80:96]:
                    print temp