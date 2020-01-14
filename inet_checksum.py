import struct

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def inet_checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i+1]
        s = carry_around_add(s, w)
    return ~s & 0xffff

if False:
    data = "45 00 00 47 73 88 40 00 40 06 a2 c4 83 9f 0e 85 83 9f 0e a1"
    data = data.split()
    data = map(lambda x: int(x,16), data)
