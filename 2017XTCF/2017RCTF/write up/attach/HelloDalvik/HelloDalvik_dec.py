from binascii import unhexlify

def dec(shift, bstr):
    bstr = bstr.replace(' ', '')
    bstr = bstr.replace('\n', '')
    bytes_ = unhexlify(bstr)
    d = [chr(v + shift) for v in bytes_]
    print(''.join(d))


def idastr():
    dec(28, '31 45 58 4C 31 49 58 4C  53 48 43 18')

    dec(43, '''04 39 36 49 36 04 39 36  41 4B 3E 40 02 38 36 38
    3D 3A 04 39 36 49 36 15  36 45 45 15 38 44 42 03
    47 38 49 3B 03 3D 3A 41  41 44 39 36 41 4B 3E 40
    ''')

    dec(17, '''
    3B 52 5E 5C 1E 61 52 63  55 1E 57 54 5B 5B 5E 53
    50 5B 65 58 5A 1E 3C 50  63 57 3C 54 63 57 5E 53
    2A
    ''')
