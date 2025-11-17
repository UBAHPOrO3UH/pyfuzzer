from pydantic import BaseModel
from typing import Any, Dict, List

class Endpoint(BaseModel):
    method: str
    path: str
    params: Dict[str, Any] | None = None
    has_auth_cookie: bool = False
    has_auth_header: bool = False

class AuthContext(BaseModel):
    cookies: Dict[str, str] = {}
    headers: Dict[str, str] = {}
    jwt_tokens: List[str] = []
