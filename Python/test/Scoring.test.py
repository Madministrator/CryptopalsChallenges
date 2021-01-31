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


if __name__ == '__main__':
    unittest.main()
