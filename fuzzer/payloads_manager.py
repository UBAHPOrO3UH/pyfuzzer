from pathlib import Path
from typing import Iterable, List
import random

SECLISTS_ROOT = Path("./SecLists")
PAYLOADS_ROOT = Path("./PayloadsAllTheThings")
MAX_PAYLOADS = 10000

def _load_wordfile(p: Path) -> List[str]:
    if not p.exists() or not p.is_file():
        return []
    try:
        txt = p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    lines = []
    for ln in txt.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)
    return lines

def _gather_from_dir(d: Path, patterns: List[str] = None, limit: int = MAX_PAYLOADS) -> List[str]:
    out = []
    if not d.exists():
        return out
    if patterns:
        for pat in patterns:
            for f in sorted(d.rglob(pat)):
                out += _load_wordfile(f)
                if len(out) >= limit:
                    return out[:limit]
    else:
        for f in sorted(d.rglob("*")):
            if f.is_file():
                out += _load_wordfile(f)
                if len(out) >= limit:
                    return out[:limit]
    return out[:limit]

def gather_passwords(limit: int = 1000) -> List[str]:
    candidates = []
    candidates += _gather_from_dir(SECLISTS_ROOT / "Passwords" / "Common-Credentials", ["*.txt"], limit=limit)
    if len(candidates) < limit:
        candidates += _gather_from_dir(SECLISTS_ROOT / "Passwords", ["*.txt"], limit=limit)
    if len(candidates) < limit:
        candidates += _gather_from_dir(PAYLOADS_ROOT / "JSON Web Token", ["*.txt", "*.lst"], limit=limit)
    if len(candidates) < limit:
        candidates += _gather_from_dir(SECLISTS_ROOT, ["*.txt"], limit=limit)

    if not candidates:
        candidates = ["password", "123456", "admin", "letmein", "qwerty", "password1"]

    seen = set()
    out = []
    for w in candidates:
        if w not in seen:
            seen.add(w)
            out.append(w)
        if len(out) >= limit:
            break
    return out

def header_payloads(limit: int = 500) -> List[str]:
    builtin = [
        "", "null", "undefined", "' OR '1'='1", "../", "%00", "admin", "root",
        "Bearer xyz", "Cookie: PHPSESSID=1", "Cookie: sessionid=1", "X-Forwarded-For: 127.0.0.1",
        "Authorization: Basic dXNlcjpwYXNz", "Authorization: Bearer ",
    ]
    extras = _gather_from_dir(SECLISTS_ROOT / "Fuzzing" / "headers", ["*.txt"], limit=limit)
    combined = builtin + extras
    return combined[:limit]

def jwt_payloads(limit: int = 1000) -> List[str]:
    out = []
    p1 = PAYLOADS_ROOT / "JSON Web Token"
    p2 = PAYLOADS_ROOT / "JSON%20Web%20Token"
    if p1.exists():
        out += _gather_from_dir(p1, ["*.txt", "*.lst"], limit=limit)
    if len(out) < limit and p2.exists():
        out += _gather_from_dir(p2, ["*.txt", "*.lst"], limit=limit)
    if len(out) < limit:
        out += _gather_from_dir(SECLISTS_ROOT / "Passwords" / "Leaked-Databases", ["*.txt"], limit=limit)
    if not out:
        out = [
            "eyJhbGciOiJub25lIn0.e30.",
            "eyJhbGciOiJIUzI1NiJ9.e30.invalidsig",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.somesig"
        ]
    seen = set(); res=[]
    for v in out:
        if v not in seen:
            seen.add(v); res.append(v)
        if len(res) >= limit:
            break
    return res

def sample(payloads: Iterable[str], n: int) -> List[str]:
    lst = list(payloads)
    if len(lst) <= n:
        return lst
    random.shuffle(lst)
    return lst[:n]

if __name__ == "__main__":
    print("SecLists root:", SECLISTS_ROOT.resolve())
    print("Payloads root:", PAYLOADS_ROOT.resolve())
    print("Passwords sample:", gather_passwords(10))
    print("Header sample:", header_payloads(10))
    print("JWT sample:", jwt_payloads(10))
