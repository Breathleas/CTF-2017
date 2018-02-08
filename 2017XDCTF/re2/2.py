for k in range(1000000):
    a="5D4A4759477D4C6836723437316E3B6E717A787E747F"
    d1 = str(303+455*k)
    a = a.decode("hex")
    data=""
    for i in range(len(a)):
        temp = ord(a[i])+48-ord(d1[i%len(d1)])
        data += chr(temp)
    if data[0:5]=='XDCTF':
        print data
#0x3226a8