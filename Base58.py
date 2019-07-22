#!/usr/bin/env python
#
# Copyright 2014 Corgan Labs
# See LICENSE.txt for distribution terms
#
# Modified by kcorlidy on 2019-05-07, because found an issue with input b"\x00\xff"*2

from hashlib import sha256
import unittest
import re

__base58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__base58_alphabet_bytes = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__base58_radix = len(__base58_alphabet)


def __string_to_int(data):
    "Convert string of bytes Python integer, MSB"
    val = 0
   
    # Python 2.x compatibility
    if type(data) == str:
        data = bytearray(data)

    for (i, c) in enumerate(data[::-1]):
        val += (256**i)*c
    return val


def encode(data):
    "Encode bytes into Bitcoin base58 string"
    enc = ''
    val = __string_to_int(data)
    while val >= __base58_radix:
        val, mod = divmod(val, __base58_radix)
        enc = __base58_alphabet[mod] + enc
    if val:
        enc = __base58_alphabet[val] + enc

    # Pad for leading zeroes
    n = len(data)-len(data.lstrip(b'\0'))
    return __base58_alphabet[0]*n + enc


def check_encode(raw):
    "Encode raw bytes into Bitcoin base58 string with checksum"
    chk = sha256(sha256(raw).digest()).digest()[:4]
    return encode(raw+chk)


def decode(data):
    "Decode Bitcoin base58 format string to bytes"
    # Python 2.x compatability
    x00 = re.findall(r"^[1]+", data)
    x00 = len(x00[0]) if x00 else 0
    
    if bytes != str:
        data = bytes(data, 'ascii')
    
    val = 0
    for (i, c) in enumerate(data[::-1]):
        val += __base58_alphabet_bytes.find(c) * (__base58_radix**i)

    dec = bytearray()
    while val >= 256:
        val, mod = divmod(val, 256)
        dec.append(mod)
    if val:
        dec.append(val)

    return b"\x00"*x00 + bytes(dec[::-1])


def check_decode(enc):
    "Decode bytes from Bitcoin base58 string and test checksum"
    dec = decode(enc)
    raw, chk = dec[:-4], dec[-4:]
    if chk != sha256(sha256(raw).digest()).digest()[:4]:
        raise ValueError("base58 decoding checksum error")
    else:
        return raw[1:]


class test(unittest.TestCase):

    def test_check_encode(self):
        data = b'now is the time for all good men to come to the aid of their country'
        enc = check_encode(data)
        self.assertEqual(check_decode(enc), data)

    def test_encode(self):
        data = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz~!@#$%^&*()_+{}|:;'<>,./?"
        enc = encode(data)
        self.assertEqual(decode(enc), data)

    def test_encode_utf8(self):
        data = b"\x00\x00\xff\xff"
        enc = encode(data)
        print(enc)
        self.assertEqual(decode(enc), data)


if __name__ == '__main__':

    unittest.main()