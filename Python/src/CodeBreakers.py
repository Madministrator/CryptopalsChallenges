# This file is not meant to be a class, rather a collection of functions to break cryptography

from itertools import combinations_with_replacement
from Python.src.Scoring import *
import sys
import string


def brute_xor(cyphertext: str, keylen: int, verbose: bool = False) -> (str, str):
    """Brute forces an XOR encrypted hex string given the cypher text and the length of key to use.
    It is not guaranteed to decipher the XOR, just give a best guess.
    :param cyphertext   The encrypted cyphertext as a hex encoded ASCII string.
    :param keylen       The guessed length of the string used as a key.
    :param verbose      Print all keys of keylen length and their corresponding decryption. Default to False.
    :returns a tuple containing the best guess key and the corresponding decryption"""
    # chars is a string of every printable character from 32 to 127 on the ASCII table
    best_score: int = sys.maxsize  # maximum size of an integer
    best_key: str = ""
    best_plaintext: str = ""

    for gen_key in combinations_with_replacement(string.printable, keylen):
        key = "".join(gen_key)
        plaintext = xor(bytes.fromhex(cyphertext), bytes(key, 'ascii')).decode('ascii')
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
    :param filename The file containing lines of XOR cypertext
    :param keylen   The suspected length of the key
    :param verbose  Prints the best guess of each line in the file.
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


def brute_repeating_key_xor(cyphertext: str, maxkeylen: int, verbose: bool = False) -> (str, str):
    """Because trying to intelligently break XOR was proving troublesome, I am attempting to brute
    force it to see if that gets consistent results, or least more accurate ones.
    :param cyphertext The cypher text we want to break
    :param maxkeylen The maximum key length to attempt to break before giving up.
    :param verbose Print processing data out to the console, defaults to False.
    :returns A tuple which contains the key and plaintext, provided the key is smaller than maxkeylen.
    """
    guesses = []
    # iterate over all possible key sizes
    for key_len in range(2, maxkeylen + 1):
        # given a guessed key length, break the cyphertext into blocks of key_len size
        blocks = [cyphertext[i:i + key_len] for i in range(0, len(cyphertext), key_len)]
        # transpose the blocks
        transposed = [""] * key_len
        for block in blocks:
            for i in range(0, len(block)):
                transposed[i] += block[i]
        # solve each transposed block as if it were a single-character XOR
        guessed_key = ""
        for block in transposed:
            key_character, guessed_plaintext = brute_xor(ascii_to_hex(block), 1, False)
            guessed_key += key_character
        # Assuming each single letter break was successful, we probably have the key, attempt decryption
        if verbose:
            print("The key could be: {}".format(guessed_key))
        guessed_plaintext = xor(bytes(cyphertext, 'ascii'), bytes(guessed_key, 'ascii')).decode()
        guessed_score = score_text(guessed_plaintext)
        guesses.append((guessed_key, guessed_plaintext, guessed_score))
    # we now have a list of the likeliest keys, plain-texts, and scores. Return the best
    guesses.sort(key=lambda l: l[2])  # sort by the guessed score from before
    if verbose:
        print("Top guesses for keys and plaintext")
        for key, plaintext, score in guesses:
            print("Key: {}, Plaintext: {}".format(key, (plaintext[:15] + '...') if len(plaintext) > 15 else plaintext))
    return guesses[0][0], guesses[0][1]


def break_repeating_key_xor(cyphertext: str, maxkeylen: int, verbose: bool = False) -> (str, str):
    """Given cypher text which has been encrypted with a repeating key XOR cypher,
    break the cypher and return the key and the plaintext.
    :param cyphertext The cypher text we want to break
    :param maxkeylen The maximum key length to attempt to break before giving up.
    :param verbose Print processing data out to the console, defaults to False.
    :returns A tuple which contains the key and plaintext, provided the key is smaller than maxkeylen.
    """
    # iterate over all possible key sizes and guess which size is likely the key
    if verbose:
        print("Scoring Key Sizes to determine likely key size. Lower scores are better.")
    # Collect a list of all key sizes and scores
    scores = []
    for key_len in range(2, maxkeylen + 1):
        # take the first keysize worth of bytes and the second keysize worth of bytes and find their hamming distance
        blocks = [cyphertext[i:i + key_len] for i in range(0, len(cyphertext), key_len)]
        distance = 0
        for i in range(1, len(blocks)):
            distance += hamming_distance(blocks[0], blocks[i]) / key_len  # normalizing along key lengths
        distance /= len(blocks)  # average of all hamming distances
        scores.append((key_len, distance))
        if verbose:
            print("Key Length: {}, Score: {}".format(key_len, distance))
    scores.sort(key=lambda l: l[1])  # sort the scores from lowest to highest since lower is better
    scores = scores[:5] + scores[-5:]  # truncate to only use the five outer scores (or less if maxkeylen is < 5)
    if verbose:
        print()  # add whitespace to output
        print("Top {} likely key lengths and their scores:".format(len(scores)))
        for key_size, score in scores:
            print("Key length: {} with score {}".format(key_size, score))
        print()

    # note that the below code is confirmed to work because it is the same as in the brute force function.
    guesses = []
    for key_len, score in scores:
        # we probably know the key size, break the cyphertext into blocks of key_len size
        blocks = [cyphertext[i:i + key_len] for i in range(0, len(cyphertext), key_len)]
        # transpose the blocks
        transposed = [""] * key_len
        for block in blocks:
            for i in range(0, len(block)):
                transposed[i] += block[i]
        # solve each transposed block as if it were a single-character XOR
        guessed_key = ""
        for block in transposed:
            key_character, guessed_plaintext = brute_xor(ascii_to_hex(block), 1, False)
            guessed_key += key_character
        # Assuming each single letter break was successful, we probably have the key, attempt decryption
        if verbose:
            print("The key could be: {}".format(guessed_key))
        guessed_plaintext = xor(bytes(cyphertext, 'ascii'), bytes(guessed_key, 'ascii')).decode()
        guessed_score = score_text(guessed_plaintext)
        guesses.append((guessed_key, guessed_plaintext, guessed_score))
    # we now have a list of the likeliest keys, plain-texts, and scores. Return the best
    guesses.sort(key=lambda l: l[2])  # sort by the guessed score from before
    if verbose:
        print("Top guesses for keys and plaintext")
        for key, plaintext, score in guesses:
            print("Key: {}, Plaintext: {}".format(key, (plaintext[:15] + '...') if len(plaintext) > 15 else plaintext))
    return guesses[0][0], guesses[0][1]


def find_ecb_line(filename: str) -> int:
    """
    Reads each line in a file and scores them on their likelihood of being ECB encrypted.
    :param filename: The name of the file to check
    :return: The line number most likely to be an ECB encrypted string
    """
    with open(filename) as file:
        lines = file.readlines()
    most_repeats = 0
    most_repeated_line = 0
    for index, line in enumerate(lines):
        score = percent_repeated_blocks(line)
        if score > most_repeats:
            most_repeats = score
            most_repeated_line = index + 1
    return most_repeated_line
