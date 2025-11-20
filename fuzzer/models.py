from pydantic import BaseModel
from typing import Any, Dict, List, Optional


class Endpoint(BaseModel):
    base_url:str
    method: str
    path: str
    params: Dict[str, Any]={}
    has_auth_cookie: bool
    has_auth_header: bool
    body: Optional[Any] = None
    headers: Dict[str, str] = {}
class AuthContext(BaseModel):
    cookies: Dict[str, str]
    headers: Dict[str, str]
    jwt_tokens: List[str]
    payload: Optional[Any] = None
