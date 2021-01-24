# This file is not meant to be a class, rather a collection of functions to break cryptography

from itertools import combinations_with_replacement
from Python.src.ByteManip import xor, hex_to_ascii
from Python.src.Scoring import score_text
import sys


def brute_xor(cyphertext: str, keylen: int, verbose: bool = False) -> (str, str):
    """Brute forces an XOR encrypted string given the cypher text and the length of key to use.
    It is not guaranteed to get the
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
