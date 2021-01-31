import unittest
from Python.src.ByteManip import *
from Python.src.CodeBreakers import *


class Challenges(unittest.TestCase):
    __doc__ = """All unit tests in this file are methods which assert that I have completed
    a cryptopals challenge. Each method is titled according to how the challenges
    are organized in the website."""

    def test_set1_challenge1(self):
        # convert hex to base 64
        hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        expected_b64 = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        self.assertEqual(hex_to_base64(hex_string), expected_b64)

    def test_set1_challenge2(self):
        # Fixed length XOR
        plaintext = "1c0111001f010100061a024b53535009181c"
        key = "686974207468652062756c6c277320657965"
        cyphertext = "746865206b696420646f6e277420706c6179"
        actual = fixed_xor(plaintext, key)
        self.assertEqual(cyphertext, actual)

    def test_set1_challenge3(self):
        # brute force single character XOR cipher
        cyphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        plaintext = "Cooking MC's like a pound of bacon"
        key = "X"
        actual_key, actual_plaintext = brute_xor(cyphertext, 1, False)
        self.assertEqual(key, actual_key)
        self.assertEqual(plaintext, actual_plaintext)

    def test_set1_challenge4(self):
        # Detect single-character XOR
        target_line_number = 171
        key = '5'
        plaintext = "Now that the party is jumping\n"
        # Note that the filename is relative and thus dependent on project structure
        ln, k, p = brute_xor_file("../../Payloads/Set1Challenge4.txt", 1, False)
        self.assertEqual(target_line_number, ln)
        self.assertEqual(key, k)
        self.assertEqual(plaintext, p)
        # Use the nuanced approach next


if __name__ == '__main__':
    unittest.main()
