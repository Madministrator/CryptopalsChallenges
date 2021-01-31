import unittest
from Python.src.Scoring import *


class ScoringTest(unittest.TestCase):
    def test_score_text(self):
        sample = "etaoin"  # the first part of the frequency string
        score = score_text(sample)
        self.assertEqual(score, 15)

    def test_score_text_probability(self):
        sample = "madministrator"
        score = 0.8825599999999999
        self.assertEqual(score, score_text_probability(sample))

    def test_hamming_distance(self):
        first = "this is a test"
        second = "wokka wokka!!!"
        actual_distance = 37
        self.assertEqual(hamming_distance(first, second), actual_distance)


if __name__ == '__main__':
    unittest.main()
