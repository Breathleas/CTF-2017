# coding=utf-8
import re
from pwn import *
import hashlib
import base64
import struct
import os
import time

HOST = '202.112.51.217'
PORT = 9999
BUFFER = 1024 

def get_md5_value(src):
    myMd5 = hashlib.md5()
    myMd5.update(src)
    myMd5_Digest = myMd5.hexdigest()
    return myMd5_Digest

def hex2charlist(hexstr):
    charlist = []
    length = len(hexstr)
    if length % 2 != 0:
        hexstr = '0' + hexstr
        length += 1
    for i in range(0, length, 2):
        charlist.append(chr(int(hexstr[i]+hexstr[i+1], 16)))
    return charlist

result=""
#bctf{3c1fffb76f147d420f984ac651505905}
#before ="626374667b33633166666662373666313437643432306639383461633635313530353930357d"
#before="626374667b3363316666666237366631"
before=""
known = ""
try:
	for l in range(0,38):
		for i in range(48,128):
			ca = []
			pa = []
			#print "[!]start========================"+str(i)+"============="
			r = remote(HOST, PORT)
			get = r.recv(BUFFER)
			#print get
			request1 = "0"*(94-len(before))
			known = request1 + before
			r.sendline(request1)
			print known
			then = r.recv(BUFFER)
			#print then
			p = then.split(':')[1].split('|')[0].strip()[2:]
			c = then.split(':')[2].strip()[2:]
			count = 0
			for j in range(0,len(c)/32):
				count = j*32	
				ca.append(c[count:count+32])
				count = 0
			j=0
			if len(known)%32 != 0:
				while(1):
					known="00"+known
					if len(known)%32 == 0:
						break	
			for j in range(0,len(known)/32):
				count = j*32	
				pa.append(known[count:count+32])
				count = 0
			#print len(ca)
			#print ca[1]
			#print pa[-1]
			#print before
			print before.decode('hex')

			#mi = len(before)%30

			p3 = '0x'+pa[-1][2:]+str(hex(i))[2:]
			#print p3
			#print "===="
			request2 = hex(eval('0x'+ca[1])^eval(p3)^eval('0x'+ca[-1]))

			#print p3
			#print '0x'+ca[1]
			#print '0x'+ca[5]
		
			then = r.recv(BUFFER)
			#print then
			#print "###"
			#print request2
			r.sendline(request2[2:])
			then = r.recv(BUFFER)
			#print then
			check = then.split(':')[2][3:35]
			#print "###"
			if check == ca[2] or check == ca[1] or check == ca[0]:
				print "ok!!!!!"
				print chr(i)
				before += str(hex(i))[2:]
				result += chr(i)
				print result
				r.close()
				continue
				#time.sleep(3)
			r.close()
		print result
	print result
except:
	print result

print result


