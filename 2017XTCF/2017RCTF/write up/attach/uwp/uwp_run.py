from Crypto.Cipher import AES
from base64 import b64decode
import sqlite3

IV = b'0000000000000000'
FAMILY_NAME = b'26a6f9cc-d019-4f5d-8a1b-a352b7738f42'
KEY = FAMILY_NAME[:16]

def decrypt(s: str):
    AES_OBJ = AES.new(KEY, AES.MODE_CBC, IV)
    text = AES_OBJ.decrypt(b64decode(s))
    pad_length = text[-1]
    return text[:-pad_length]

def main():
    for line in open('table').readlines():
        d = decrypt(line)
        if d.find(b'RCTF') == 0:
            print(d)

main()
