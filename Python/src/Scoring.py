

# "etaoinsrhldcumfpgwybvkxjqz ETAOINSRHLDCUMFPGWYBVKXJQZ.?!1234567890" # standard default
# "etaoin srhldcumfpgwybvkxjqzETAOINSRHLDCUMFPGWYBVKXJQZ0123456789.?!" # higher space & numeral preference
# The frequency string was made a parameter so that you could inject strings based on frequency analysis of text files.
def score_text(text: str, frequency: str = "etaoinsrhldcumfpgwybvkxjqz ETAOINSRHLDCUMFPGWYBVKXJQZ.?!1234567890") -> int:
    """Scores a string on its resemblance to english text by using letter frequency.
    The lower the returned integer, the better the score.
    :parameter text The ascii string to score
    :parameter frequency A "letter frequency string" to use as a scoring metric. Defaults to etoin shrdlu based string.
    :returns an integer score on the resemblance on the string to English text, where a low score is preferred."""
    score: int = 0
    # actual scoring algorithm
    for c in text:
        index = frequency.find(c)
        score += index if index >= 0 else 255  # punish characters not found in the high frequency string.
    return score
