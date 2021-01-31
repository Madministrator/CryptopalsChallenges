# This file is not meant to be a class, rather a collection of functions to break cryptography

from itertools import combinations_with_replacement
from Python.src.ByteManip import *
from Python.src.Scoring import *
import sys


def brute_xor(cyphertext: str, keylen: int, verbose: bool = False) -> (str, str):
    """Brute forces an XOR encrypted hex string given the cypher text and the length of key to use.
    It is not guaranteed to decipher the XOR, just give a best guess.
    :parameter cyphertext   The encrypted cyphertext as a hex encoded ASCII string.
    :parameter keylen       The guessed length of the string used as a key.
    :parameter verbose      Print all keys of keylen length and their corresponding decryption. Default to False.
    :returns a tuple containing the best guess key and the corresponding decryption"""
    # chars is a string of every printable character from 32 to 127 on the ASCII table
    chars = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
    best_score: int = sys.maxsize  # maximum size of an integer
    best_key: str = ""
    best_plaintext: str = ""

    for gen_key in combinations_with_replacement(chars, keylen):
        key = "".join(gen_key)
        plaintext = hex_to_ascii(xor(cyphertext, key.encode().hex()))
        if verbose:
            print(key, plaintext)
        score = score_text(plaintext)
        if score < best_score:
            best_score = score
            best_key = key
            best_plaintext = plaintext

    # return the best results
    return best_key, best_plaintext


def brute_xor_file(filename: str, keylen: int, verbose: bool = False) -> (int, str, str):
    """Applies the brute force algorithm on an entire file where each file has been
    XOR encrypted line by line to find which line was encrypted and what the decrypted message
    reads as.
    :parameter filename The file containing lines of XOR cypertext
    :parameter keylen   The suspected length of the key
    :parameter verbose  Prints the best guess of each line in the file.
    :returns a tuple containing the best guess line number, the best guess key, and the
                corresponding decrypted string.
    """
    # First, read in the file
    with open(filename) as fp:
        line_number = 0
        best_score: int = sys.maxsize  # maximum size of an integer
        best_key: str = ""
        best_plaintext: str = ""
        best_line_number: int = 0
        while True:
            line_number += 1
            line = fp.readline().strip()
            if not line:
                if verbose:
                    print("Reached end of file")
                break
            # Now we can do processing on the line
            # print("Line {}: {}".format(line_number, line.strip()))
            try:
                hex_to_ascii(line)
            except UnicodeDecodeError:
                # Not hex, so move on
                if verbose:
                    print("Line {}: Not Hex encoded, skipping".format(line_number))
                continue
            key, plaintext = brute_xor(line, keylen, False)
            score = score_text(plaintext)
            if score < best_score:
                best_score = score
                best_key = key
                best_plaintext = plaintext
                best_line_number = line_number
            if verbose:
                print("Line {}: Best Key: {}, Resulting Plaintext: {}".format(line_number, key, plaintext))
        # return best guess from the entire file
        return best_line_number, best_key, best_plaintext


def break_repeating_key_xor(cyphertext: str, maxkeylen: int, verbose: bool = False) -> (str, str):
    """Given cypher text which has been encrypted with a repeating key XOR cypher,
    break the cypher and return the key and the plaintext.
    :parameter cyphertext The cypher text we want to break
    :parameter maxkeylen The maximum key length to attempt to break before giving up.
    :parameter verbose Print processing data out to the console, defaults to False.
    :returns A tuple which contains the key and plaintext, provided the key is smaller than maxkeylen.
    """
    # iterate over all possible key sizes and guess which size is likely the key
    if verbose:
        print("Scoring Key Sizes to determine likely key size. Lower scores are better.")
    best_key_size = 0
    best_key_score = sys.maxsize
    for key_size in range(2, maxkeylen):
        # take the first keysize worth of bytes and the second keysize worth of bytes and find their hamming distance
        first_chunk = cyphertext[0: key_size]
        second_chunk = cyphertext[key_size: key_size + key_size]
        distance = hamming_distance(first_chunk, second_chunk) / key_size  # / key_size normalizes key sizes
        if distance < best_key_score:
            best_key_score = distance
            best_key_size = key_size
        if verbose:
            print("Key Length: {}, Score: {}".format(key_size, distance))
    if verbose:
        print("Likeliest key length: {} with score: {}".format(best_key_size, best_key_score))
    # we probably know the key size, break the cyphertext into blocks of key size length
    blocks = [cyphertext[i:i + best_key_size] for i in range(0, len(cyphertext), best_key_size)]
    # transpose the blocks. Make a block that is the first byte of every block, and a block that is the second byte, etc
    transposed = [""] * best_key_size
    for block in blocks:
        for i in range(0, len(block)):
            transposed[i] += block[i]
    # solve each transposed block as if it were a single-character XOR
    key = ""
    for block in transposed:
        key_character, plaintext = brute_xor(ascii_to_hex(block), 1, False)
        key += key_character
        if verbose:
            print("Letter of Key: {}, resulting values: {}".format(key_character, plaintext))
    # Assuming each single letter break was successful, we probably have the key, attempt decryption
    if verbose:
        print("The key is likely to be: {}".format(key))
    plaintext = hex_to_ascii(xor(ascii_to_hex(cyphertext), ascii_to_hex(key)))

    return key, plaintext
