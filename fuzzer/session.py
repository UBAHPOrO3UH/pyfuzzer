import httpx
from typing import Optional, Dict, Any

class SessionManager:
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        assert self._client is not None, "session not initialized"
        return self._client

    async def post(self, path: str, data: Dict[str, Any], headers: Dict[str, str] = None):
        url = f"{self.base_url}{path}"
        return await self.client.post(url, data=data, headers=headers or {})

    async def get(self, path: str, params: Dict[str, Any] = None, headers: Dict[str, str] = None):
        url = f"{self.base_url}{path}"
        return await self.client.get(url, params=params or {}, headers=headers or {})

    async def login_form(self, login_path: str, method: str, fields: Dict[str, Any]):
        if method.upper() == "POST":
            return await self.post(login_path, data=fields)
        return await self.get(login_path, params=fields)
