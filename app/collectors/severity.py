"""Conservative text fallback; English abbreviations must be whole words."""
import re


def guess_severity(text):
    text = text or ""
    rules = [
        ("CRITICAL", r"\b(?:critical|rce|remote code(?: execution)?|code execution|in-the-wild|actively exploited)\b", ("严重", "在野")),
        ("HIGH", r"\b(?:high|important)\b", ("高危",)),
        ("MEDIUM", r"\b(?:medium|moderate)\b", ("中危",)),
        ("LOW", r"\blow\b", ("低危",)),
    ]
    for severity, pattern, words in rules:
        if re.search(pattern, text, re.I) or any(word in text for word in words):
            return severity
    return "UNKNOWN"
