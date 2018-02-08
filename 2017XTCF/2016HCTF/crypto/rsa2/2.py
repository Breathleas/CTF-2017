import hashlib
import base64
import struct
Prefix="KhshQCE="
Prefix=base64.b64decode(Prefix)
for i in range(0,256):
    for j in range(0,256):
        for m in range(0,256):
            for n in range(0,256):
                suffix = struct.pack("B",i)+struct.pack("B",j)+struct.pack("B",m)+struct.pack("B",n)
                content = Prefix + suffix
                sha512value = hashlib.sha512(content).hexdigest()
                if "fffffff" in sha512value:
                    print i,j,m,n
                    print sha512value
                    suffix = base64.b64encode(suffix)
                    print suffix

#b66888c818c08d932ea91b8d6a1f122c2y7ZAdbh