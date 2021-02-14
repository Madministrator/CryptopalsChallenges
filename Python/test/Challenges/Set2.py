import unittest
from Python.src.ByteManip import *


class Set2(unittest.TestCase):
    def test_pad_block(self):
        # implement PKCS#7 padding
        before = "YELLOW SUBMARINE"
        expected = "YELLOW SUBMARINE\x04\x04\x04\x04"
        actual = pad_block(bytes(before, "utf-8"), 20).decode()
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    unittest.main()
