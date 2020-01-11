#!/usr/bin/python3

import binascii
import sys
from z3 import *

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

class CrcInstance():
    def __init__(self, crclen=16, messagewords=1, given_message_bytes=None, given_crcstart=None, given_crcxor=None, given_crcresult=None, given_polynomial=None, swapbytes=False):
        self.s = Solver()
        assert crclen % 8 == 0
        self.crclen_bits=crclen
        self.crclen_bytes = crclen//8
        self.crclen_hexits = crclen//4
        self.message = [BitVec('messageword%d-%03d' % (crclen,i),crclen) for i in range(messagewords)]
        self.polynomial = BitVec('polynomial',crclen)
        self.crcstart = BitVec('crcstart',crclen)
        self.crcxor = BitVec('crcxor',crclen)
        if given_crcstart != None:
            self.s.add(self.crcstart == given_crcstart)
        if given_crcxor != None:
            self.s.add(self.crcxor == given_crcxor)
        if given_message_bytes != None:
            assert len(given_message_bytes) == self.crclen_bytes * messagewords
            n=0
            for word in range(0,len(given_message_bytes),self.crclen_bytes):
                worddata=given_message_bytes[word:word+self.crclen_bytes]
                assert len(worddata) == self.crclen_bytes
                self.s.add(self.message[n] == 0)
                n+=1
        if given_polynomial != None:
            self.s.add(self.polynomial == given_polynomial)
        self.crcresult = BitVec('crcresult', crclen)
        self.s.add(self.crcresult == self.z3crc())
        if given_crcresult != None:
            self.s.add(self.crcresult == given_crcresult)
    def z3crc(self):
        crc = self.crcstart
        for c in self.message:
            for block in range(self.crclen_bits-8, -1, -8):
                crc ^= LShR(c, block) & 0xFF
                for i in range(8):
                    crc = If(crc & 1 == BitVecVal(1, self.crclen_bits), LShR(crc, 1) ^ self.polynomial, LShR(crc, 1))
        return crc ^ self.crcxor
    def check(self):
        print(self.s.check())
    def model(self):
        return self.s.model()
    def results(self, title=''):
        checkresult=self.check()
        m = self.model()
        polynomial_value=m[self.polynomial].as_long()
        crcresult_value=m[self.crcresult].as_long()
        print('{title:20s} polynomial: 0x{num:0{width}x} crc result: 0x{crcnum:0{crcwidth}x}'.format(title=title,num=polynomial_value, width=self.crclen_hexits, crcnum=crcresult_value, crcwidth=self.crclen_hexits))

# i used https://www.lammertbies.nl/comm/info/crc-calculation to generate some test vectors
# i used the c code https://github.com/lammertb/libcrc to find all the parameters
crc_presets = {
        'crc16':              {'crclen': 16, 'given_polynomial':     0xA001, 'given_crcstart':     0x0000, 'given_crcxor':     0x0000, 'swapbytes': False},
        'crc16-modbus':       {'crclen': 16, 'given_polynomial':     0xA001, 'given_crcstart':     0xffff, 'given_crcxor':     0x0000, 'swapbytes': False},
        'crc16-sick':         {'crclen': 16, 'given_polynomial':     0x8005, 'given_crcstart':     0x0000, 'given_crcxor':     0x0000, 'swapbytes': False},
        'crc-ccitt-xmodem':   {'crclen': 16, 'given_polynomial':     0x1021, 'given_crcstart':     0x0000, 'given_crcxor':     0x0000, 'swapbytes': False},
        'crc-ccitt-ffff':     {'crclen': 16, 'given_polynomial':     0x1021, 'given_crcstart':     0xffff, 'given_crcxor':     0x0000, 'swapbytes': False},
        'crc-ccitt-1d0f':     {'crclen': 16, 'given_polynomial':     0x1021, 'given_crcstart':     0x1d0f, 'given_crcxor':     0x0000, 'swapbytes': False},
        'crc-ccitt-kermit':   {'crclen': 16, 'given_polynomial':     0x8408, 'given_crcstart':     0x0000, 'given_crcxor':     0x0000, 'swapbytes': True},
        'crc-dnp':            {'crclen': 16, 'given_polynomial':     0xA6BC, 'given_crcstart':     0x0000, 'given_crcxor':     0xffff, 'swapbytes': True},
        'crc-32':             {'crclen': 32, 'given_polynomial': 0xEDB88320, 'given_crcstart': 0xFFFFFFFF, 'given_crcxor': 0xffffffff, 'swapbytes': False},
}

for message in [[1,1]]:
    print('message %s' % message)
    for crc_preset in crc_presets:
        config = crc_presets[crc_preset]
        crclen_bits=config['crclen']
        assert crclen_bits % 8 == 0
        crclen_bytes=config['crclen']//8
        if len(message) % crclen_bytes != 0:
            continue
        messagewords = len(message) // crclen_bytes
        crctest = CrcInstance(given_message_bytes=message, messagewords=messagewords, **config)
        crctest.results(crc_preset)
    print()

