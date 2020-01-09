#!/usr/bin/python3

import crcmod
import libscrc
import binascii
import sys

inputs = b"""
 0: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 00 ff 01 03 00 00 00 00 ff 00 00 00 00 ff e8 19
 1: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 01 ff 01 03 00 00 00 00 ff 00 00 00 00 ff 3c 33
 2: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 02 ff 01 03 00 00 00 00 ff 00 00 00 00 ff 51 c4
 3: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 03 ff 01 03 00 00 00 00 ff 00 00 00 00 ff 85 ee
 4: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 04 ff 01 03 00 00 00 00 ff 00 00 00 00 ff 8a 2a
 5: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 05 ff 01 03 00 00 00 00 ff 00 00 00 00 ff 5e 00
 6: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 06 ff 01 03 00 00 00 00 ff 00 00 00 00 ff 33 f7
 7: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 07 ff 01 03 00 00 00 00 ff 00 00 00 00 ff e7 dd
 8: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 08 ff 01 03 00 00 00 00 ff 00 00 00 00 ff 2c 7f
 9: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 09 ff 01 03 00 00 00 00 ff 00 00 00 00 ff f8 55
10: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 0a ff 01 03 00 00 00 00 ff 00 00 00 00 ff 95 a2
11: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 0b ff 01 03 00 00 00 00 ff 00 00 00 00 ff 41 88
12: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 0c ff 01 03 00 00 00 00 ff 00 00 00 00 ff 4e 4c
13: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 0d ff 01 03 00 00 00 00 ff 00 00 00 00 ff 9a 66
14: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 0e ff 01 03 00 00 00 00 ff 00 00 00 00 ff f7 91
15: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 0f ff 01 03 00 00 00 00 ff 00 00 00 00 ff 23 bb
16: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 10 ff 01 03 00 00 00 00 ff 00 00 00 00 ff 71 5c
17: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 11 ff 01 03 00 00 00 00 ff 00 00 00 00 ff a5 76
18: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 12 ff 01 03 00 00 00 00 ff 00 00 00 00 ff c8 81
19: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 13 ff 01 03 00 00 00 00 ff 00 00 00 00 ff 1c ab
20: 00 00 00 00 00 ff 41 04 8c 55 4b 00 16 ff 00 01 00 00 00 14 ff 01 03 00 00 00 00 ff 00 00 00 00 ff 13 6f
"""


class DataCrc():
    def getbytes(self, line):
        return bytearray([int(x, 16) for x in line])
    def __init__(self, inputline, crclen=2):
        assert crclen > 0
        assert crclen <= 4
        self.crclen = crclen
        inputs_bytes = inputline.split()[1:]
        inputs_bytes = self.getbytes(inputs_bytes) 
        self.framebytes = inputs_bytes
        self.databytes = self.framebytes[0:-crclen]
        self.crcbytes = self.framebytes[-crclen:]
        self.line = inputline
        assert len(self.framebytes) == len(self.databytes) + len(self.crcbytes)
        assert len(self.crcbytes) == crclen
    def xor(self,a,b):
        return bytearray([a ^ b for (a, b) in zip(a, b)])
    def __add__(self,b):
        assert self.crclen == b.crclen
        addition = DataCrc(self.line, self.crclen)
        addition.framebytes = self.xor(self.framebytes, b.framebytes)
        addition.databytes = self.xor(self.databytes, b.databytes)
        addition.crcbytes = self.xor(self.crcbytes, b.crcbytes)
        return addition
    def hex(self,inbytes):
        hexstr=["%02x" % (inbyte,) for inbyte in inbytes]
        return ' '.join(hexstr)
    def __str__(self):
        return "data %s crc %s crclen %d" % (self.hex(self.databytes), self.hex(self.crcbytes), self.crclen)
    def __eq__(self,b):
        return self.framebytes==b.framebytes and self.crclen == b.crclen
    def __hash__(self):
        return hash(self.__str__())

class DataCrcGroup():
    def __init__(self,crclen=2):
        self.set=set()
        assert crclen > 0
        assert crclen <= 4
        self.crclen=crclen
    def add(self, line):
        newcrc=DataCrc(line, self.crclen)
        if newcrc in self.set:
            return
        additions=set()
        for k in self.set:
            additions.add(k+newcrc)
        self.set |= additions
        self.add(newcrc)
        print('closure added %d plus new' % (len(additions)))

group=DataCrcGroup()

lines = inputs.split(b'\n')

for line in lines:
    if len(line) < 10:
        continue
    group.add(line)
