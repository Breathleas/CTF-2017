import hashlib
check="4746bbbd02bb590fbeac2821ece8fc5cad749265ca7503ef4386b38fc12c4227b03ecc45a7ec2da7be3c5ffe121734e8"
for w in range(0,6):
	for i in range(48,123):
	    for j in range(48,123):
	        for m in range(48,123):
	            for n in range(48,123):
	                temp = chr(i)+chr(j)+chr(m)+chr(n)
	                hashvalue = hashlib.md5(temp).hexdigest()
	                if hashvalue[0:16] == check[w*16:w*16+16]:
	                    print w,temp