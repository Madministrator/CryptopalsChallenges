import sys
from Python.src.ByteManip import *
from collections import Counter

# "etaoinsrhldcumfpgwybvkxjqz ETAOINSRHLDCUMFPGWYBVKXJQZ.?!1234567890" # standard default
# "etaoin srhldcumfpgwybvkxjqzETAOINSRHLDCUMFPGWYBVKXJQZ0123456789.?!" # higher space & numeral preference
# The frequency string was made a parameter so that you could inject strings based on frequency analysis of text files.
def score_text(text: str, frequency: str = "etaoinsrhldcumfpgwybvkxjqz ETAOINSRHLDCUMFPGWYBVKXJQZ.?!1234567890") -> int:
    """Scores a string on its resemblance to english text by using letter frequency.
    The lower the returned integer, the better the score.
    :param text The ascii string to score
    :param frequency A "letter frequency string" to use as a scoring metric. Defaults to etoin shrdlu based string.
    :returns an integer score on the resemblance of the string to English text, where a low score is preferred."""
    score: int = 0
    # actual scoring algorithm
    for c in text:
        index = frequency.find(c)
        score += index if index >= 0 else 255  # punish characters not found in the high frequency string.
    return score


# This isn't used outside of a test context, but I have it here as an alternative for fun.
def score_text_probability(text: str) -> int:
    """Scores a string on its resemblance to english text by comparing letter frequencies
    to the most common letters in the english alphabet based on the wikipedia page on letter
    frequencies (https://en.wikipedia.org/wiki/Letter_frequency). In this function, the higher
    the score, the better.
    :param text The utf-8 string to score
    :returns an integer score on the resemblance of the string to English text, where a higher score is preferred."""
    english_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253, 'e': .12702,
        'f': .02228, 'g': .02015, 'h': .06094, 'i': .06094, 'j': .00153,
        'k': .00772, 'l': .04025, 'm': .02406, 'n': .06749, 'o': .07507,
        'p': .01929, 'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150, 'y': .01974,
        'z': .00074, ' ': .13000
    }
    # This could be substituted with other languages pretty easily by using the table from the
    # same Wiki article. The dictionary itself could be expanded to use accented characters too.
    # We could also contemplate generating one of these tables programmatically by reading in text files.
    return sum([english_frequencies.get(chr(byte), 0) for byte in bytes(text, 'utf-8').lower()])


def hamming_distance(str1: str, str2: str) -> int:
    """Determines the hamming distance between two ascii strings. Hamming distance is the number
    of differing bits between two pieces of information.
    :param str1 The first string
    :param str2 The second string
    :returns    The Hamming distance between the two strings
    """
    bytes1 = bytes(str1, "ascii")
    bytes2 = bytes(str2, "ascii")
    # determine which string is shorter and measure the difference in length of bytes
    bytelen = len(bytes1) if len(bytes1) < len(bytes2) else len(bytes2)
    distance = abs(len(bytes1) - len(bytes2)) * sys.getsizeof(int)  # if they are the same size, distance will be zero
    # count the number of differing bits
    for i in range(0, bytelen):
        # The number of 1 bits in compared is the number of differing bits
        compared = bytes1[i] ^ bytes2[i]
        distance += count_set_bits(compared)

    return distance


def percent_repeated_blocks(text: str, block_length: int = 16) -> float:
    """
    Checks how many repeating blocks there are in the text, which is a indication/vulnerability of ECB encryption.
    :param text   The text in question we are checking for encryption.
    :param block_length The length of each block to compare for repeats, defaults to 16-bit blocks.
    :return:    A float which is the percent of blocks which repeat, a indication of ECB encryption.
    """
    # break the string down into block_length sized blocks
    blocks = [text[i:i + block_length] for i in range(0, len(text), block_length)]
    counts = list(Counter(blocks).values())
    repeats = 0
    for i in range(0, len(counts)):
        if counts[i] > 1:
            repeats += counts[i]
    return repeats / len(blocks)
