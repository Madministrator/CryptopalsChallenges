import unittest
from Python.src.CodeBreakers import *
from base64 import b64decode
import timeit
from Crypto.Cipher import AES


class Set1(unittest.TestCase):
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
        ln, k, p = brute_xor_file("../../../Payloads/Set1Challenge4.txt", 1, False)
        self.assertEqual(target_line_number, ln)
        self.assertEqual(key, k)
        self.assertEqual(plaintext, p)

    def test_set1_challenge5(self):
        # Implement repeating-key XOR
        plaintext_line = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        key = "ICE"
        cyphertext_line = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a" \
                          "652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        self.assertEqual(cyphertext_line, xor(bytes(plaintext_line, 'utf-8'), bytes(key, 'utf-8')).hex())

    def test_set1_challenge6_brute(self):
        # load in the cyphertext file
        expected_key = "Terminator X: Bring the noise"  # Note: key length = 29
        with open("../../../Payloads/Set1Challenge6.txt") as file:
            cyphertext = b64decode(file.read().replace('\n', '')).decode()
            expected_plaintext = xor(bytes(cyphertext, "ascii"), bytes(expected_key, "ascii")).decode("ascii")
        # Timing code will show the difference between brute forcing and intelligent guessing
        start = timeit.default_timer()
        key, plaintext = brute_repeating_key_xor(cyphertext, 40, False)
        elapsed = timeit.default_timer() - start
        print("Time to brute force repeated key XOR: {}".format(elapsed))
        self.assertEqual(expected_key, key)
        self.assertEqual(expected_plaintext, plaintext)

    def test_set1_challenge6_break(self):
        # load in the cyphertext file
        expected_key = "Terminator X: Bring the noise"
        with open("../../../Payloads/Set1Challenge6.txt") as file:
            cyphertext = b64decode(file.read().replace('\n', '')).decode()
            expected_plaintext = xor(bytes(cyphertext, "ascii"), bytes(expected_key, "ascii")).decode("ascii")
        # Timing code will show how much faster this method is than brute forcing
        start = timeit.default_timer()
        key, plaintext = break_repeating_key_xor(cyphertext, 40, False)
        elapsed = timeit.default_timer() - start
        print("Time to break repeated key XOR: {}".format(elapsed))
        self.assertEqual(expected_key, key)
        self.assertEqual(expected_plaintext, plaintext)

    def test_set1_challenge7(self):
        # Decrypt AES-128-ECB mode
        with open("../../../Payloads/Set1Challenge7.txt") as file:
            cyphertext: str = file.read().replace('\n', '')
            cyphertext = b64decode(cyphertext)
        # I didn't implement this, I'm just using the pycrypto library to encrypt/decrypt
        cipher = AES.new("YELLOW SUBMARINE", AES.MODE_ECB)
        plaintext: str = cipher.decrypt(cyphertext).decode()
        expected_plaintext_start = "I'm back and I'm ringin' the bell"
        self.assertTrue(plaintext.startswith(expected_plaintext_start))

    def test_set1_challenge8(self):
        # Detect ECB encryption
        filename = "../../../Payloads/Set1Challenge8.txt"
        expected_line_number = 133
        actual_line_number = find_ecb_line(filename)
        self.assertEqual(expected_line_number, actual_line_number)


if __name__ == '__main__':
    unittest.main()
