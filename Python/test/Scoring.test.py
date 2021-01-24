import unittest
from Python.src.Scoring import score_text


class ScoringTest(unittest.TestCase):
    def test_score_text(self):
        sample = "etaoin"  # the first part of the frequency string
        score = score_text(sample)
        self.assertEqual(score, 15)


if __name__ == '__main__':
    unittest.main()
