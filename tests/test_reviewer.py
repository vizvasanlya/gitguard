from pathlib import Path

from gitguard.core.reviewer import CodeReviewer


def test_reviewer_init():
    reviewer = CodeReviewer()
    assert reviewer is not None


def test_review_python_file():
    reviewer = CodeReviewer()
    content = '"""Module docstring."""\n\ndef hello():\n    pass\n'
    result = reviewer.review_file(Path("test.py"), content)

    assert result.score > 0
    assert result.summary


def test_review_long_lines():
    reviewer = CodeReviewer()
    content = 'x = "aaaaabbbbbcccccdddddeeeeefffffggggghhhhhaaaaabbbbbcccccdddddeeeeefffffggggghhhhhaaaaabbbbbcccccdddddeeeeefffffggggghhhhhaaaaabbbbbccccc"\n'
    result = reviewer.review_file(Path("test.py"), content)

    assert len(result.issues) > 0
    assert any(i.rule_id == "STYLE001" for i in result.issues)


def test_review_missing_docstring():
    reviewer = CodeReviewer()
    content = 'def hello():\n    pass\n'
    result = reviewer.review_file(Path("test.py"), content)

    assert any(i.rule_id == "STYLE003" for i in result.issues)


def test_review_diff():
    reviewer = CodeReviewer()
    diff = """--- a/test.py
+++ b/test.py
@@ -1 +1,3 @@
+def hello():
+    pass
+print("done")
"""
    result = reviewer.review_diff(diff)
    assert result.score > 0


def test_review_score():
    reviewer = CodeReviewer()
    content = 'x = "a" * 200\n' * 10
    result = reviewer.review_file(Path("test.py"), content)

    assert result.score < 100


def test_review_suggestions():
    reviewer = CodeReviewer()
    content = 'from os import *\nfrom sys import *\n' * 10
    result = reviewer.review_file(Path("test.py"), content)

    assert len(result.suggestions) > 0
