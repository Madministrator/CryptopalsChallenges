import unittest
from Python.src.ByteManip import *
from Crypto.Cipher import AES
from base64 import b64decode


class Set2(unittest.TestCase):
    def test_set2_challenge9(self):
        # implement PKCS#7 padding
        before = "YELLOW SUBMARINE"
        expected = "YELLOW SUBMARINE\x04\x04\x04\x04"
        actual = pad_block(bytes(before, "utf-8"), 20).decode()
        self.assertEqual(expected, actual)

    def test_set2_challenge10(self):
        # implement cbc mode
        with open("../../../Payloads/Set2Challenge10.txt") as file:
            cyphertext: str = b64decode(file.read().replace('\n', ''))
        key = "YELLOW SUBMARINE"
        # IV is 16 bytes of ASCII zeros
        initialization_vector = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        cipher = AES.new(key, AES.MODE_CBC, initialization_vector)
        plaintext: str = cipher.decrypt(cyphertext).decode()
        expected_plaintext_start = "I'm back and I'm ringin' the bell"
        self.assertTrue(plaintext.startswith(expected_plaintext_start))

if __name__ == '__main__':
    unittest.main()
