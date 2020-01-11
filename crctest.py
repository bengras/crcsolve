import crc8
from PyCRC.CRC16 import CRC16
from PyCRC.CRC16DNP import CRC16DNP
from PyCRC.CRC16Kermit import CRC16Kermit
from PyCRC.CRC16SICK import CRC16SICK
from PyCRC.CRC32 import CRC32
from PyCRC.CRCCCITT import CRCCCITT

class mycrc8:
    def __init__(self):
        pass
    def calculate(self, inbytes):
        hash = crc8.crc8()
        hash.update(inbytes)
        return int(hash.hexdigest(),16)

classdict =  {
'crc8': mycrc8(),
'crc16': CRC16(),
'crc16-modbus': CRC16(modbus_flag=True),
'crc16-sick': CRC16SICK(),
'crc-ccitt-xmodem': CRCCCITT(version='XModem'),
'crc-ccitt-ffff': CRCCCITT(version='FFFF'),
'crc-ccitt-1d0f': CRCCCITT(version='1D0F'),
'crc-ccitt-kermit': CRC16Kermit(),
'crc-dnp': CRC16DNP(),
'crc-32': CRC32(),
}

def crctest(name, inputbytes=b'\0'):
    if name not in classdict:
        raise Exception('unknown crc name %s' % name)
    return classdict[name].calculate(inputbytes)
