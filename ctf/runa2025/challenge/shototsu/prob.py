def _ror(x, n):
    x &= 0xFFFFFFFF
    return ((x << (32 - n)) | (x >> n)) & 0xFFFFFFFF

def _rol(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def encrypt(data: bytes) -> bytes:
    h0 = 0x67452301 
    h1 = 0xEFCDAB89 
    h2 = 0x98BADCFE 
    h3 = 0x10325476 

    m = data
    bit_len_le = (len(m) * 8).to_bytes(8, "little")
    m += b"\x80"
    m += b"\x00" * ((56 - (len(m) % 64)) % 64)
    m += bit_len_le

    
    for off in range(0, len(m), 64):
        block = m[off:off+64]
        X = [int.from_bytes(block[i:i+4], "little") for i in range(0, 64, 4)]

        a, b, c, d = h0, h1, h2, h3

        s1 = (3, 7, 11, 19)
        for i in range(16):
            k = i
            r = s1[i & 3]
            if   (i & 3) == 0:
                f = (b & c) | ((~b & 0xFFFFFFFF) & d)
                a = _rol((a + f + X[k]) & 0xFFFFFFFF, r)
            elif (i & 3) == 1:
                f = (a & b) | ((~a & 0xFFFFFFFF) & c)
                d = _rol((d + f + X[k]) & 0xFFFFFFFF, r)
            elif (i & 3) == 2:
                f = (d & a) | ((~d & 0xFFFFFFFF) & b)
                c = _rol((c + f + X[k]) & 0xFFFFFFFF, r)
            else:
                f = (c & d) | ((~c & 0xFFFFFFFF) & a)
                b = _rol((b + f + X[k]) & 0xFFFFFFFF, r)

        s2 = (3, 5, 9, 13); C2 = 0x5A827999
        order2 = [0,4,8,12, 1,5,9,13, 2,6,10,14, 3,7,11,15]
        for i in range(16):
            k = order2[i]; r = s2[i & 3]
            if   (i & 3) == 0:
                g = (b & c) | (b & d) | (c & d)
                a = _rol((a + g + X[k] + C2) & 0xFFFFFFFF, r)
            elif (i & 3) == 1:
                g = (a & b) | (a & c) | (b & c)
                d = _rol((d + g + X[k] + C2) & 0xFFFFFFFF, r)
            elif (i & 3) == 2:
                g = (d & a) | (d & b) | (a & b)
                c = _rol((c + g + X[k] + C2) & 0xFFFFFFFF, r)
            else:
                g = (c & d) | (c & a) | (d & a)
                b = _rol((b + g + X[k] + C2) & 0xFFFFFFFF, r)

        s3 = (3, 9, 11, 15); C3 = 0x6ED9EBA1
        order3 = [0,8,4,12, 2,10,6,14, 1,9,5,13, 3,11,7,15]
        for i in range(16):
            k = order3[i]; r = s3[i & 3]
            if   (i & 3) == 0:
                h_ = (b ^ c ^ d) & 0xFFFFFFFF
                a = _rol((a + h_ + X[k] + C3) & 0xFFFFFFFF, r)
            elif (i & 3) == 1:
                h_ = (a ^ b ^ c) & 0xFFFFFFFF
                d = _rol((d + h_ + X[k] + C3) & 0xFFFFFFFF, r)
            elif (i & 3) == 2:
                h_ = (d ^ a ^ b) & 0xFFFFFFFF
                c = _rol((c + h_ + X[k] + C3) & 0xFFFFFFFF, r)
            else:
                h_ = (c ^ d ^ a) & 0xFFFFFFFF
                b = _rol((b + h_ + X[k] + C3) & 0xFFFFFFFF, r)

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF

    return (h0.to_bytes(4, "little") +
            h1.to_bytes(4, "little") +
            h2.to_bytes(4, "little") +
            h3.to_bytes(4, "little"))

def get_flag():
    with open("./flag", "r") as f:
        flag = f.read().strip()
    print(flag)

print("I make a simple crypto system but holy example collision!!")
t1 = bytes.fromhex("839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edc45e51fe39708bf9427e9c3e8b9")
t2 = bytes.fromhex("839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edd45e51fe39708bf9427e9c3e8b9")
print(f"message1 (hex): {t1.hex()}")
print(f"message2 (hex): {t2.hex()}")
print(encrypt(t1) == encrypt(t2) and t1==t2)

print("Can you find?")

try:
    first = bytes.fromhex(input("message1 (hex): "))
except ValueError:
    print("16진수 형식이 아닙니다.")
    raise SystemExit(1)

try:
    second = bytes.fromhex(input("message2 (hex): "))
except ValueError:
    print("16진수 형식이 아닙니다.")
    raise SystemExit(1)

if encrypt(first) == encrypt(second) and first!=second and first != t1 and first != t2:
    get_flag()
else:
    print("No")

