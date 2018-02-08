from idaapi import *
from idc import *
addr = 0x40107c


for i in range(0x79):
    PatchByte(addr+i,(Byte(addr+i)^162)+34)

data = 0
i = addr
flag = ""
while i < addr+0x79:
    print GetDisasmEx(i,0)
    if GetOpnd(i,0) == "bl":
        i = NextHead(i)
        continue
    if GetOpnd(i,0) == "dl":
        i = NextHead(i)
        continue
    if GetOpnd(i,1) == "bl":
        temp = 0x65
    elif GetOpnd(i,1) == "dl":
        temp = 0x5f
    else:
        temp = GetOperandValue(i,1)
    flag += chr(temp)
    i = NextHead(i)
print flag