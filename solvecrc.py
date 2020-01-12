from z3 import *

class CrcInstance():
    def __init__(self, lsbfirst=True, crclen=16, n_messagebytes=0, given_message_bytes=None, given_crcstart=None, given_crcxor=None, given_crcresult=None, given_polynomial=None, swapbytes=False):
        self.s = Solver()
        assert crclen % 8 == 0
        self.lsbfirst = lsbfirst
        self.crclen_bits=crclen
        self.crclen_bytes = crclen//8
        self.crclen_hexits = crclen//4
        self.messagebytes = [BitVec('messagebyte-%03d' % i,8) for i in range(n_messagebytes)]
        self.polynomial = BitVec('polynomial',crclen)
        self.crcstart = BitVec('crcstart',crclen)
        self.crcxor = BitVec('crcxor',crclen)
        if given_crcstart != None:
            self.s.add(self.crcstart == given_crcstart)
        if given_crcxor != None:
            self.s.add(self.crcxor == given_crcxor)
        if given_message_bytes != None:
            assert len(given_message_bytes) == n_messagebytes
            for b in range(n_messagebytes):
                worddata=given_message_bytes[b]
                self.s.add(self.messagebytes[b] == BitVecVal(worddata, 8))
        if given_polynomial != None:
            self.s.add(self.polynomial == given_polynomial)

        self.crcresult = BitVec('crcresult', self.crclen_bits)
        self.s.add(self.crcresult == self.z3crc())
        if given_crcresult != None:
            self.s.add(self.crcresult == given_crcresult)
    def z3crc(self):
        crc = self.crcstart
        bits=0
        messagebytes=0
        for message_byte in self.messagebytes:
                if self.crclen_bits > 8:
                    extbyte = ZeroExt(self.crclen_bits-8, message_byte)
                    if not self.lsbfirst:
                        extbyte = extbyte << (self.crclen_bits-8)
                else:
                    extbyte = message_byte
                messagebytes+=1
                crc ^= extbyte

                intermediate_messagebyte = BitVec('messagebyte_intermediate%d' % messagebytes, 8)
                self.s.add(intermediate_messagebyte == message_byte)

                for i in range(8):
                    bits+=1
                    intermediate_crcresult = BitVec('crcstate%d' % bits, self.crclen_bits)
                    self.s.add(intermediate_crcresult == crc)
                    if self.lsbfirst:
                        mask=1
                        crc = If(crc & mask == BitVecVal(mask, self.crclen_bits), LShR(crc, 1) ^ self.polynomial, LShR(crc, 1))
                    else:
                        mask=1 << (self.crclen_bits-1)
                        crc = If(crc & mask == BitVecVal(mask, self.crclen_bits), (crc >> 1) ^ self.polynomial, crc >> 1)
                    intermediate_crcresult = BitVec('intermediate_crcresult%d' % bits, self.crclen_bits)
                    self.s.add(intermediate_crcresult == crc)
        return crc ^ self.crcxor
    def check(self):
        print(self.s.check())
    def model(self):
        return self.s.model()
    def results(self, title='', full=False):
        checkresult=self.check()
        m = self.model()
        polynomial_value=m[self.polynomial].as_long()
        crcresult_value=m[self.crcresult].as_long()
        if Full:
            for d in m.decls():
                print("%s = %s" % (d.name(), m[d]))
        return crcresult_value
        print('{title:20s} polynomial: 0x{num:0{width}x} crc result: 0x{crcnum:0{crcwidth}x}'.format(title=title,num=polynomial_value, width=self.crclen_hexits, crcnum=crcresult_value, crcwidth=self.crclen_hexits))
