from idaapi import *
from idc import *

addr = 0x401539
end = 0x40154c
for i in range(0x401539,0x40154c):
    PatchByte(i,0x90)

addr = 0x401366
end = 0x401388
for i in range(addr,end):
    PatchByte(i,0x90)