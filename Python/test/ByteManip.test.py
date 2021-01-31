import unittest
from Python.src.ByteManip import *


class ByteManipTest(unittest.TestCase):
    def test_hex_to_base64(self):
        """The actual test case from Cryptopals challenges."""
        hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        expected_b64 = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        self.assertEqual(hex_to_base64(hex_string), expected_b64)

    def test_is_hex(self):
        hex_str = "01234567890abcdefABCDEF"
        rnd_str = "Not a hex encoded string"
        self.assertTrue(is_hex(hex_str))
        self.assertFalse(is_hex(rnd_str))

    def test_ascii_to_hex(self):
        ascii = "ascii string"
        hex = "617363696920737472696e67"
        self.assertEqual(hex, ascii_to_hex(ascii))

    def test_ascii_to_hex_preserve_newlines(self):
        ascii = "Has\nnewlines"
        round_trip = hex_to_ascii(ascii_to_hex(ascii))
        self.assertEqual(ascii, round_trip)

    def test_fixed_xor(self):
        """The actual test case from Cryptopals challenges."""
        plaintext = "1c0111001f010100061a024b53535009181c"
        key = "686974207468652062756c6c277320657965"
        cyphertext = "746865206b696420646f6e277420706c6179"
        actual = fixed_xor(plaintext, key)
        self.assertEqual(cyphertext, actual)

    def test_fixed_xor_exceptions(self):
        try:
            fixed_xor("a", "aaa")  # different lengths, valid hex
            self.assertFalse(True)
        except ValueError:
            self.assertTrue(True) # pass case
        try:
            fixed_xor("bobby", "alice")  # same length, not hex
            self.assertFalse(True)
        except ValueError:
            self.assertTrue(True)

    def test_fixed_xor_order(self):  # Test that parameter order doesn't matter
        str1 = "1234567890abcdef"
        str2 = "abcdef0987654321"
        self.assertEqual(fixed_xor(str1, str2), fixed_xor(str2, str1))

    def test_xor_same_length_keys(self):
        plaintext = "1c0111001f010100061a024b53535009181c"
        key = "686974207468652062756c6c277320657965"
        cyphertext = "746865206b696420646f6e277420706c6179"
        actual = xor(plaintext, key)
        self.assertEqual(cyphertext, actual)

    def test_xor_different_length_keys(self):
        plaintext = "1c0111001f010100061a024b53535009181c"
        key = "1234"
        cyphertext = "0e3503340d351334142e107f4167423d0a28"
        actual = xor(plaintext, key)
        self.assertEqual(cyphertext, actual)

    def test_count_set_bits(self):
        self.assertEqual(count_set_bits(10), 2)
        self.assertEqual(count_set_bits(32), 1)
        self.assertEqual(count_set_bits(12345), 6)


if __name__ == '__main__':
    unittest.main()
