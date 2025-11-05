# fuzzer/jwt_utils.py
import jwt
import base64
import json

def jwt_none_alg(original_token: str) -> str:
    try:
        header_b, payload_b, sig = original_token.split(".")
    except Exception:
        return original_token
    try:
        header = json.loads(base64.urlsafe_b64decode(pad_b64(header_b)).decode())
        header["alg"] = "none"
        h2 = base64.urlsafe_b64encode(json.dumps(header, separators=(",",":")).encode()).decode().rstrip("=")
        return f"{h2}.{payload_b}."
    except Exception:
        return original_token

def pad_b64(s: str) -> str:
    return s + "=" * (-len(s) % 4)

def corrupt_signature(token: str) -> str:
    parts = token.split(".")
    if len(parts)!=3: return token+"A"
    return f"{parts[0]}.{parts[1]}.corruptsig"

def forge_with_key(payload: dict, key: str, alg="HS256") -> str:
    return jwt.encode(payload, key, algorithm=alg)
