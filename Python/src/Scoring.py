

# "etaoinsrhldcumfpgwybvkxjqz ETAOINSRHLDCUMFPGWYBVKXJQZ.?!1234567890" # standard default
# "etaoin srhldcumfpgwybvkxjqzETAOINSRHLDCUMFPGWYBVKXJQZ0123456789.?!" # higher space & numeral preference
# The frequency string was made a parameter so that you could inject strings based on frequency analysis of text files.
def score_text(text: str, frequency: str = "etaoinsrhldcumfpgwybvkxjqz ETAOINSRHLDCUMFPGWYBVKXJQZ.?!1234567890") -> int:
    """Scores a string on its resemblance to english text by using letter frequency.
    The lower the returned integer, the better the score.
    :parameter text The ascii string to score
    :parameter frequency A "letter frequency string" to use as a scoring metric. Defaults to etoin shrdlu based string.
    :returns an integer score on the resemblance of the string to English text, where a low score is preferred."""
    score: int = 0
    # actual scoring algorithm
    for c in text:
        index = frequency.find(c)
        score += index if index >= 0 else 255  # punish characters not found in the high frequency string.
    return score


def score_text_probability(text: str):
    """Scores a string on its resemblance to english text by comparing letter frequencies
    to the most common letters in the english alphabet based on the wikipedia page on letter
    frequencies (https://en.wikipedia.org/wiki/Letter_frequency). In this function, the higher
    the score, the better.
    :parameter text The utf-8 string to score
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
    # We could also contemplate generating one of these tables programatically by reading in text files.
    return sum([english_frequencies.get(chr(byte), 0) for byte in bytes(text, 'utf-8').lower()])

