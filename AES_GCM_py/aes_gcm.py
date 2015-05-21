#!/usr/bin/env python
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long


# GF(2^128) defined by 1 + a + a^2 + a^7 + a^128
# Please note the MSB is x0 and LSB is x127
def gf_2_128_mul(x, y):
    assert x < (1 << 128)
    assert y < (1 << 128)
    res = 0
    for i in range(127, -1, -1):
        res ^= x * ((y >> i) & 1)  # branchless
        x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
    assert res < 1 << 128
    return res


class InvalidInputException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return str(self.msg)


class InvalidTagException(Exception):
    def __str__(self):
        return 'The authenticaiton tag is invalid.'


# Galois/Counter Mode with AES-128 and 96-bit IV
class AES_GCM:
    def __init__(self, master_key):
        self.change_key(master_key)

    def change_key(self, master_key):
        if master_key >= (1 << 128):
            raise InvalidInputException('Master key should be 128-bit')

        self.__master_key = long_to_bytes(master_key, 16)
        self.__aes_ecb = AES.new(self.__master_key, AES.MODE_ECB)
        self.__auth_key = bytes_to_long(self.__aes_ecb.encrypt(b'\x00' * 16))

        # precompute the table for multiplication in finite field
        table = []  # for 8-bit
        for i in range(16):
            row = []
            for j in range(256):
                row.append(gf_2_128_mul(self.__auth_key, j << (8 * i)))
            table.append(tuple(row))
        self.__pre_table = tuple(table)

        self.prev_init_value = None  # reset

    def __times_auth_key(self, val):
        res = 0
        for i in range(16):
            res ^= self.__pre_table[i][val & 0xFF]
            val >>= 8
        return res

    def __ghash(self, aad, txt):
        len_aad = len(aad)
        len_txt = len(txt)

        # padding
        if 0 == len_aad % 16:
            data = aad
        else:
            data = aad + b'\x00' * (16 - len_aad % 16)
        if 0 == len_txt % 16:
            data += txt
        else:
            data += txt + b'\x00' * (16 - len_txt % 16)

        tag = 0
        assert len(data) % 16 == 0
        for i in range(len(data) / 16):
            tag ^= bytes_to_long(data[i * 16: (i + 1) * 16])
            tag = self.__times_auth_key(tag)
            # print 'X\t', hex(tag)
        tag ^= ((8 * len_aad) << 64) | (8 * len_txt)
        tag = self.__times_auth_key(tag)

        return tag

    def encrypt(self, init_value, plaintext, auth_data=b''):
        if init_value >= (1 << 96):
            raise InvalidInputException('IV should be 96-bit')
        # a naive checking for IV reuse
        if init_value == self.prev_init_value:
            raise InvalidInputException('IV must not be reused!')
        self.prev_init_value = init_value

        len_plaintext = len(plaintext)
        # len_auth_data = len(auth_data)

        if len_plaintext > 0:
            counter = Counter.new(
                nbits=32,
                prefix=long_to_bytes(init_value, 12),
                initial_value=2,  # notice this
                allow_wraparound=True)
            aes_ctr = AES.new(self.__master_key, AES.MODE_CTR, counter=counter)

            if 0 != len_plaintext % 16:
                padded_plaintext = plaintext + \
                    b'\x00' * (16 - len_plaintext % 16)
            else:
                padded_plaintext = plaintext
            ciphertext = aes_ctr.encrypt(padded_plaintext)[:len_plaintext]

        else:
            ciphertext = b''

        auth_tag = self.__ghash(auth_data, ciphertext)
        # print 'GHASH\t', hex(auth_tag)
        auth_tag ^= bytes_to_long(self.__aes_ecb.encrypt(
                                  long_to_bytes((init_value << 32) | 1, 16)))

        # assert len(ciphertext) == len(plaintext)
        assert auth_tag < (1 << 128)
        return ciphertext, auth_tag

    def decrypt(self, init_value, ciphertext, auth_tag, auth_data=b''):
        if init_value >= (1 << 96):
            raise InvalidInputException('IV should be 96-bit')
        if auth_tag >= (1 << 128):
            raise InvalidInputException('Tag should be 128-bit')

        if auth_tag != self.__ghash(auth_data, ciphertext) ^ \
                bytes_to_long(self.__aes_ecb.encrypt(
                long_to_bytes((init_value << 32) | 1, 16))):
            raise InvalidTagException

        len_ciphertext = len(ciphertext)
        if len_ciphertext > 0:
            counter = Counter.new(
                nbits=32,
                prefix=long_to_bytes(init_value, 12),
                initial_value=2,
                allow_wraparound=True)
            aes_ctr = AES.new(self.__master_key, AES.MODE_CTR, counter=counter)

            if 0 != len_ciphertext % 16:
                padded_ciphertext = ciphertext + \
                    b'\x00' * (16 - len_ciphertext % 16)
            else:
                padded_ciphertext = ciphertext
            plaintext = aes_ctr.decrypt(padded_ciphertext)[:len_ciphertext]

        else:
            plaintext = b''

        return plaintext


if __name__ == '__main__':
    master_key = 0x00000000000000000000000000000000
    plaintext = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    auth_data = b''
    init_value = 0x000000000000000000000000
    ciphertext = b'\x42\xca\x99\x8a\x25\xf0\xe4\xda' + \
                 b'\xba\x62\x89\xf5\x3c\xfc\xb1\x28' + \
                 b'\xa6\xc7\xf9\xff\x1c\x1d\x0e\x7b' + \
                 b'\xae\xa7\xe8\x9d\xf7\xef\xa4\x86' + \
                 b'\x47\x6a\x78\x4b\x25\x1f\xf9\xb4' + \
                 b'\x4f\xf9\xc7\xde\xa3\xe7\xde\x96' + \
                 b'\xbe\x35\xdb\x63\x21\xbf\x1b\x4e' + \
                 b'\x4f\x4b\x8a\x8b\xf1\xfa'
    auth_tag = 0xd2752fd2c4310e79669058f1d6344c1f

    print 'plaintext:', hex(bytes_to_long(plaintext))

    my_gcm = AES_GCM(master_key)
    encrypted, new_tag = my_gcm.encrypt(init_value, plaintext, auth_data)
    print 'encrypted:', hex(bytes_to_long(encrypted))
    print 'auth tag: ', hex(new_tag)

    try:
        decrypted = my_gcm.decrypt(init_value, encrypted,
                new_tag + 1, auth_data)
    except InvalidTagException:
        decrypted = my_gcm.decrypt(init_value, encrypted, new_tag, auth_data)
        print 'decrypted:', hex(bytes_to_long(decrypted))
