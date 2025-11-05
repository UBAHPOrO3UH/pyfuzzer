from typing import Iterable, List

COMMON_PASSWORDS = [
    "password", "123456", "admin", "letmein", "qwerty", "password1", "12345678", "111111"
]

def generate_passwords(max_items: int = None) -> Iterable[str]:
    suffixes = ["", "1", "123", "!", "2023", "Admin"]
    out = []
    for w in COMMON_PASSWORDS:
        for s in suffixes:
            out.append(f"{w}{s}")
            if max_items and len(out) >= max_items:
                return out
    return out
