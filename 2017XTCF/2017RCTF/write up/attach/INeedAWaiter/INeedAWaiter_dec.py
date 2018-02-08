from binascii import unhexlify

RET = unhexlify('fc55e53d4bee0c96a781e1cffe7f3dce433242df298f2a97edc235eb191c9da6d22116cdba99beb14ca6d4bd77098e0797')
# push x[11], x[15], ...
INDEX = [11, 15, 14, 13, 7, 9, 6, 3, 0, 1, 2, 10, 5, 12, 8, 4]

def get_fn():
    n = RET[-1] ^ 66
    def fn():
        nonlocal n
        n = (123 * n + 59) % 65536
        return n
    return fn

def get_reordered_input(fn):
    return [v ^ (fn() % 256) for v in RET[:-1]]

def get_transformed_input(ri):
    rounds = len(ri) // len(INDEX)
    result = list()
    for r in range(rounds):
        dst_buf = ri[r * len(INDEX): (r + 1) * len(INDEX)]
        src_buf = [-1] * len(INDEX)
        for i in range(len(INDEX)):
            src_buf[INDEX[i]] = dst_buf[i]
        result.extend(src_buf)
    return result

def get_original_input(ti):
    r = list()
    for v in ti:
        if ord('a') <= v <= ord('z'):
            r.append((v - ord('a') + 13) % 26 + ord('a'))
        elif ord('A') <= v <= ord('Z'):
            r.append((v - ord('A') + 13) % 26 + ord('A'))
        else:
            r.append(v)
    return r

def to_str(x):
    return bytes(x).decode('UTF-8')

fn = get_fn()
reordered_input = get_reordered_input(fn)
transformed_input = get_transformed_input(reordered_input)
original_input = get_original_input(transformed_input)
print(to_str(original_input))
