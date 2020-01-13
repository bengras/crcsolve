from z3 import *

class CrcInstances():
    def __init__(self,
            databyte_lsbfirst=True, crclen=16, given_crcstart=None, given_crcxor=None, given_polynomial=None, swapbytes=False, zeropad=True, add_message_bytewise=True):
        self.solver = Solver()
        self.databyte_lsbfirst = databyte_lsbfirst
        self.crclen = crclen
        self.given_crcstart = given_crcstart
        self.given_crcxor = given_crcxor
        self.given_polynomial = given_polynomial
        self.swapbytes = swapbytes
        self.zeropad = zeropad
        self.add_message_bytewise = add_message_bytewise
        self.instances=[]
        self.crcresults=[]
        self.polynomial, self.crcstart, self.crcxor = None, None, None
    def add_instance(self,  given_crcresult=None, given_message_bytes=None, n_messagebytes=0):
        assert given_crcresult != None or given_message_bytes != None
        if given_message_bytes != None:
            assert len(given_message_bytes) == n_messagebytes
        instance = CrcInstance(databyte_lsbfirst=self.databyte_lsbfirst, crclen=self.crclen, n_messagebytes=n_messagebytes, given_message_bytes=given_message_bytes,
                given_crcstart=self.given_crcstart, given_crcxor=self.given_crcxor, given_crcresult=given_crcresult, given_polynomial=self.given_polynomial, swapbytes=self.swapbytes,
                zeropad=self.zeropad, add_message_bytewise=self.add_message_bytewise, use_solver=self.solver, message_instance=len(self.instances), use_polynomial=self.polynomial, use_crcstart=self.crcstart, use_crcxor=self.crcxor)
#        print('single instance results: crc %x' % instance.results(full=False))
        self.instances.append(instance)
        self.polynomial, self.crcstart, self.crcxor, new_crcresult = instance.get_vars()
        self.crcresults.append(new_crcresult)
    def results(self, title='', full=False):
        checkresult=self.solver.check()
        if checkresult == z3.unsat:
            raise Exception('no solution')
        print('result:', checkresult)
        m = self.solver.model()
        polynomial_value=m[self.polynomial].as_long()
        crcstart_value=m[self.crcstart].as_long()
        crcxor_value=m[self.crcxor].as_long()
        print(self.crcresults)
        crcresults=[m[x].as_long() for x in self.crcresults]
        if full:
            for d in m.decls():
                print("%40s = 0x%04x = %s" % (d.name(), m[d].as_long(), '{:016b}'.format((m[d].as_long()))))
        return polynomial_value, crcstart_value, crcxor_value, crcresults

class CrcInstance():
    def __init__(self, databyte_lsbfirst=True, crclen=16, n_messagebytes=0, given_message_bytes=None, given_crcstart=None, given_crcxor=None, given_crcresult=None, given_polynomial=None, swapbytes=False, zeropad=True, add_message_bytewise=True, use_solver=None, use_polynomial=None, use_crcstart=None, use_crcxor=None, message_instance=0):
        if use_solver == None:
            self.s = Solver()
        else:
            self.s = use_solver
        assert crclen % 8 == 0
        self.message_instance=message_instance
        self.databyte_lsbfirst = databyte_lsbfirst
        self.crclen_bits=crclen
        self.crclen_bytes = crclen//8
        if zeropad:
            if n_messagebytes != None:
                n_messagebytes += self.crclen_bytes
            if given_message_bytes != None:
                given_message_bytes = given_message_bytes + ([0]*self.crclen_bytes)
        self.crclen_hexits = crclen//4
        self.messagebytes = [BitVec('messagebyte-%d-%03d' % (self.message_instance,i),8) for i in range(n_messagebytes)]
        self.polynomial = use_polynomial
        self.crcstart = use_crcstart
        self.crcxor = use_crcxor
        if self.polynomial == None:
            self.polynomial = BitVec('polynomial',crclen)
        if self.crcstart == None:
            self.crcstart = BitVec('crcstart',crclen)
        if self.crcxor == None:
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

        self.crcresult_var = BitVec('crcresult%d_var' % self.message_instance, self.crclen_bits)
        self.crcresult = BitVec('crcresult%d' % self.message_instance, self.crclen_bits)
        self.s.add(self.crcresult_var == self.z3crc(add_message_bytewise))
        if swapbytes:
            assert crclen == 16
            self.crcresult_var = (self.crcresult_var << 8) | LShR(self.crcresult_var, 8)
        self.s.add(self.crcresult_var == self.crcresult)
        if given_crcresult != None:
            self.s.add(self.crcresult_var == given_crcresult)
    def get_vars(self):
        return self.polynomial, self.crcstart, self.crcxor, self.crcresult
    def z3crc(self, add_message_bytewise):
        crc = self.crcstart
        bits=0
        messagebytes=0
        for message_byte in self.messagebytes:
                if add_message_bytewise:
                    if self.crclen_bits > 8:
                        extbyte = ZeroExt(self.crclen_bits-8, message_byte)
                        if not self.databyte_lsbfirst:
                            extbyte = extbyte << (self.crclen_bits-8)
                    else:
                        extbyte = message_byte
                    crc ^= extbyte
                messagebytes+=1

#                intermediate_messagebyte = BitVec('messagebyte_intermediate%02d' % messagebytes, 8)
#                self.s.add(intermediate_messagebyte == message_byte)

                for i in range(8):
                    bits+=1
#                    intermediate_crcresult = BitVec('crcstate%02d' % bits, self.crclen_bits)
#                    self.s.add(intermediate_crcresult == crc)
                    if self.databyte_lsbfirst:
                        mask=1
#                        intermediate_hitresult = BitVec('intermediate_lsb_hitresult%02d' % bits, self.crclen_bits)
#                        self.s.add(intermediate_hitresult == crc & mask)
                        crc = If(crc & mask == BitVecVal(mask, self.crclen_bits), LShR(crc, 1) ^ self.polynomial, LShR(crc,1))
                    else:
                        mask=1 << (self.crclen_bits-1)
#                        intermediate_hitresult = BitVec('intermediate_msb_hitresult%02d' % bits, self.crclen_bits)
#                        self.s.add(intermediate_hitresult == crc & mask)
                        crc = If(crc & mask == BitVecVal(mask, self.crclen_bits), (crc << 1)  ^ self.polynomial, (crc << 1) )
                    if not add_message_bytewise:
                        if self.databyte_lsbfirst:
                            extbyte = LShR((ZeroExt(self.crclen_bits-8, message_byte) & BitVecVal(1 << i, self.crclen_bits)),i) << (self.crclen_bits-1)
                        else:
                            extbyte = LShR(ZeroExt(self.crclen_bits-8, message_byte) & BitVecVal(0x80 >> i, self.crclen_bits), (7-i))
                        crc ^= extbyte
#                    intermediate_crcresult = BitVec('intermediate_crcresult%02d' % bits, self.crclen_bits)
#                    self.s.add(intermediate_crcresult == crc)
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
        if full:
            for d in m.decls():
                print("%40s = 0x%04x = %s" % (d.name(), m[d].as_long(), '{:016b}'.format((m[d].as_long()))))
        return crcresult_value
        print('{title:20s} polynomial: 0x{num:0{width}x} crc result: 0x{crcnum:0{crcwidth}x}'.format(title=title,num=polynomial_value, width=self.crclen_hexits, crcnum=crcresult_value, crcwidth=self.crclen_hexits))
