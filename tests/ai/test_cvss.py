"""Tests for ai/cvss.py: scores are calculated locally from a vector, never taken from the AI."""

import pytest

from webrecon.ai import cvss


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),     # the classic reflected XSS
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),     # scope changed: PR:L weighs 0.68, not 0.62
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
    ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N", 0.0),     # no impact at all
    # Worked by hand: exploitability 8.22*0.2*0.44*0.27*0.62 = 0.1211, impact 6.42*(1-0.78^3) = 3.3734,
    # sum 3.4945, rounded up to one decimal = 3.5.
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.5),
])
def test_scores_match_the_cvss_31_formula(vector, score):
    assert cvss.evaluate(vector).score == score


@pytest.mark.parametrize("score,rating", [(0.0, "None"), (0.1, "Low"), (3.9, "Low"), (4.0, "Medium"), (6.9, "Medium"),
                                          (7.0, "High"), (8.9, "High"), (9.0, "Critical"), (10.0, "Critical")])
def test_rating_bands(score, rating):
    assert cvss.rating(score) == rating


def test_roundup_is_the_specifications_function_not_ordinary_rounding():
    assert cvss.roundup(4.0) == 4.0
    assert cvss.roundup(4.02) == 4.1            # always up
    assert cvss.roundup(4.000001) == 4.0        # the 3.1 fix for floating point noise
    assert cvss.roundup(9.95) == 10.0


def test_the_vector_is_normalised_whatever_order_and_case_it_arrives_in():
    shuffled = " cvss:3.1/a:n/i:n/c:l/s:u/ui:n/pr:n/ac:h/av:n "
    result = cvss.evaluate(shuffled)
    assert result.vector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
    assert (result.score, result.rating) == (3.7, "Low")


@pytest.mark.parametrize("vector", [
    "", None, 7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                 # empty, not text, no prefix
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # other versions
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",                           # a metric is missing
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P",                   # an unknown (temporal) metric
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                       # a value that does not exist
    "CVSS:3.1/AV:NN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                      # two letters
    "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                  # a metric twice
    "CVSS:3.1/AV/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                         # no value
])
def test_invalid_vectors_are_rejected(vector):
    assert cvss.evaluate(vector) is None
