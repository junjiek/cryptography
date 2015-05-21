#!/usr/bin/env python
from aes_gcm import AES_GCM
from pprint import pprint
from Crypto.Random.random import getrandbits
from Crypto.Util.number import long_to_bytes

test_cases = ({
    'master_key': 0x00000000000000000000000000000000,
    'plaintext':  b'',
    'auth_data':  b'',
    'init_value': 0x000000000000000000000000,
    'ciphertext': b'',
    'auth_tag':   0x58e2fccefa7e3061367f1d57a4e7455a,
}, {
    'master_key': 0x00000000000000000000000000000000,
    'plaintext':  b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    'auth_data':  b'',
    'init_value': 0x000000000000000000000000,
    'ciphertext': b'\x42\xca\x99\x8a\x25\xf0\xe4\xda' +
                  b'\xba\x62\x89\xf5\x3c\xfc\xb1\x28' +
                  b'\xa6\xc7\xf9\xff\x1c\x1d\x0e\x7b' +
                  b'\xae\xa7\xe8\x9d\xf7\xef\xa4\x86' +
                  b'\x47\x6a\x78\x4b\x25\x1f\xf9\xb4' +
                  b'\x4f\xf9\xc7\xde\xa3\xe7\xde\x96' +
                  b'\xbe\x35\xdb\x63\x21\xbf\x1b\x4e' +
                  b'\x4f\x4b\x8a\x8b\xf1\xfa',
    'auth_tag':   0xd2752fd2c4310e79669058f1d6344c1f,
}, {
    'master_key': 0x00000000000000000000000000000000,
    'plaintext':  b'\x00\x00\x00\x00\x00\x00\x00\x00' +
                  b'\x00\x00\x00\x00\x00\x00\x00\x00',
    'auth_data':  b'',
    'init_value': 0x000000000000000000000000,
    'ciphertext': b'\x03\x88\xda\xce\x60\xb6\xa3\x92' +
                  b'\xf3\x28\xc2\xb9\x71\xb2\xfe\x78',
    'auth_tag':   0xab6e47d42cec13bdf53a67b21257bddf,
}, {
    'master_key': 0xfeffe9928665731c6d6a8f9467308308,
    'plaintext':  b'\xd9\x31\x32\x25\xf8\x84\x06\xe5' +
                  b'\xa5\x59\x09\xc5\xaf\xf5\x26\x9a' +
                  b'\x86\xa7\xa9\x53\x15\x34\xf7\xda' +
                  b'\x2e\x4c\x30\x3d\x8a\x31\x8a\x72' +
                  b'\x1c\x3c\x0c\x95\x95\x68\x09\x53' +
                  b'\x2f\xcf\x0e\x24\x49\xa6\xb5\x25' +
                  b'\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57' +
                  b'\xba\x63\x7b\x39\x1a\xaf\xd2\x55',
    'auth_data':  b'',
    'init_value': 0xcafebabefacedbaddecaf888,
    'ciphertext': b'\x42\x83\x1e\xc2\x21\x77\x74\x24' +
                  b'\x4b\x72\x21\xb7\x84\xd0\xd4\x9c' +
                  b'\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0' +
                  b'\x35\xc1\x7e\x23\x29\xac\xa1\x2e' +
                  b'\x21\xd5\x14\xb2\x54\x66\x93\x1c' +
                  b'\x7d\x8f\x6a\x5a\xac\x84\xaa\x05' +
                  b'\x1b\xa3\x0b\x39\x6a\x0a\xac\x97' +
                  b'\x3d\x58\xe0\x91\x47\x3f\x59\x85',
    'auth_tag':   0x4d5c2af327cd64a62cf35abd2ba6fab4,
}, {
    'master_key': 0xfeffe9928665731c6d6a8f9467308308,
    'plaintext':  b'\xd9\x31\x32\x25\xf8\x84\x06\xe5' +
                  b'\xa5\x59\x09\xc5\xaf\xf5\x26\x9a' +
                  b'\x86\xa7\xa9\x53\x15\x34\xf7\xda' +
                  b'\x2e\x4c\x30\x3d\x8a\x31\x8a\x72' +
                  b'\x1c\x3c\x0c\x95\x95\x68\x09\x53' +
                  b'\x2f\xcf\x0e\x24\x49\xa6\xb5\x25' +
                  b'\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57' +
                  b'\xba\x63\x7b\x39',
    'auth_data':  b'\xfe\xed\xfa\xce\xde\xad\xbe\xef' +
                  b'\xfe\xed\xfa\xce\xde\xad\xbe\xef' +
                  b'\xab\xad\xda\xd2',
    'init_value': 0xcafebabefacedbaddecaf888,
    'ciphertext': b'\x42\x83\x1e\xc2\x21\x77\x74\x24' +
                  b'\x4b\x72\x21\xb7\x84\xd0\xd4\x9c' +
                  b'\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0' +
                  b'\x35\xc1\x7e\x23\x29\xac\xa1\x2e' +
                  b'\x21\xd5\x14\xb2\x54\x66\x93\x1c' +
                  b'\x7d\x8f\x6a\x5a\xac\x84\xaa\x05' +
                  b'\x1b\xa3\x0b\x39\x6a\x0a\xac\x97' +
                  b'\x3d\x58\xe0\x91',
    'auth_tag':   0x5bc94fbc3221a5db94fae95ae7121a47,
})


if __name__ == '__main__':
    num_failures = 0

    for test_data in test_cases:
        test_gcm = AES_GCM(test_data['master_key'])
        encrypted, tag = test_gcm.encrypt(
            test_data['init_value'],
            test_data['plaintext'],
            test_data['auth_data']
        )

        states = []
        tags = []
        ivs = []
        aads = []

        # extra encryptions
        s = encrypted
        for i in range(1000):
            iv = getrandbits(96)
            a = long_to_bytes(getrandbits(1024))
            s, t = test_gcm.encrypt(iv, s, a)
            states.append(s)
            tags.append(t)
            ivs.append(iv)
            aads.append(a)

        # extra decryptions
        for i in range(999, -1, -1):
            assert s == states[i]
            iv = ivs[i]
            t = tags[i]
            a = aads[i]
            s = test_gcm.decrypt(iv, s, t, a)
        encrypted = s

        decrypted = test_gcm.decrypt(
            test_data['init_value'],
            encrypted,
            tag,
            test_data['auth_data']
        )

        if encrypted != test_data['ciphertext'] or \
                tag != test_data['auth_tag'] or \
                decrypted != test_data['plaintext']:
            num_failures += 1
            print 'This test case failed:'
            pprint(test_data)
            print

    if num_failures == 0:
        print 'All test cases passed!'
    else:
        print num_failures, 'test cases failed in total.'
