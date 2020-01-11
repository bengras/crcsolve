from z3 import *

class CrcInstance():
    def __init__(self, lsbfirst=True, crclen=16, messagewords=1, given_message_bytes=None, given_crcstart=None, given_crcxor=None, given_crcresult=None, given_polynomial=None, swapbytes=False):
        self.s = Solver()
        assert crclen % 8 == 0
        self.lsbfirst = lsbfirst
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

        self.crcresult = BitVec('crcresult', self.crclen_bits)
        self.s.add(self.crcresult == self.z3crc())
        if given_crcresult != None:
            self.s.add(self.crcresult == given_crcresult)
    def z3crc(self):
        crc = self.crcstart
        for c in self.message:
            for block in range(self.crclen_bits-8, -1, -8):
                message_byte = LShR(c, block) & 0xFF
                if self.lsbfirst:
                    crc ^= message_byte
                else:
                    crc ^= message_byte << (self.crclen_bits-8)
                for i in range(8):
                    if self.lsbfirst:
                        mask=1
                        crc = If(crc & mask == BitVecVal(mask, self.crclen_bits), LShR(crc, 1) ^ self.polynomial, LShR(crc, 1))
                    else:
                        mask=1 << self.crclen_bits-1
                        crc = If(crc & mask == BitVecVal(mask, self.crclen_bits), (crc >> 1) ^ self.polynomial, crc >> 1)
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
        return crcresult_value
        print('{title:20s} polynomial: 0x{num:0{width}x} crc result: 0x{crcnum:0{crcwidth}x}'.format(title=title,num=polynomial_value, width=self.crclen_hexits, crcnum=crcresult_value, crcwidth=self.crclen_hexits))
