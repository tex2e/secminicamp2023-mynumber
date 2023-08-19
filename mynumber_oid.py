# OIDとバイト列の変換

import math


class OID:

    @staticmethod
    def byte2str(oid_bytes: bytes) -> str:
        """バイト列からOID文字列への変換"""
        hex_list = [ch for ch in oid_bytes]
        x = int(hex_list[0] / 40)
        y = int(hex_list[0] % 40)
        if x > 2:
            y += (x-2)*40
            x = 2
        OID_str = str(x) + '.' + str(y)
        val = 0
        for byte in range(1, len(hex_list)):
            val = ((val<<7) | ((hex_list[byte] & 0x7F)))
            if (hex_list[byte] & 0x80) != 0x80:
                OID_str += "." + str(val)
                val = 0
        return OID_str

    @staticmethod
    def str2byte(oid_str: str) -> bytes:
        hex_list = []
        numbers = oid_str.split('.')
        a, b = numbers[0:2]
        hex_list.append(int(a)*40 + int(b))
        for num in numbers[2:]:
            num_bin = bin(int(num, 10))[2:]
            chunk_count = math.ceil(len(num_bin) / 7)
            num_zeropad = str(num_bin).zfill(chunk_count * 7)
            for i in range(chunk_count):
                msb = 1
                if i == chunk_count - 1: # if last chunk
                    msb = 0
                a_num = int(num_zeropad[i*7:(i+1)*7], 2)
                a_num |= msb << 7
                hex_list.append(a_num)
        return bytearray(hex_list)


if __name__ == '__main__':
    print('OID -> Bytes:', OID.str2byte('1.2.840.113549.2.5').hex())
    print('Bytes -> OID:', OID.byte2str(b'\x2A\x86\x48\x86\xF7\x0D\x02\x05'))

    print("[*] SHA256:")
    print('OID -> Bytes:', OID.str2byte('2.16.840.1.101.3.4.2.1').hex())
