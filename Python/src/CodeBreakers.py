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
