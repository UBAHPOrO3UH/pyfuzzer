from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List

import httpx
from pydantic import BaseModel

from fuzzer.runners.storage import Endpoint, AuthContext


class AttackResult(BaseModel):
    vulnerability: str
    endpoint: str
    severity: str = "medium"
    evidence: Dict[str, Any]


class AttackStrategy(ABC):
    name: str

    @abstractmethod
    def applicable(self, endpoint: Endpoint, ctx: AuthContext) -> bool:
        """Можно ли применять атаку к данному эндпоинту и контексту."""
        raise NotImplementedError

    @abstractmethod
    async def run(
        self,
        endpoint: Endpoint,
        ctx: AuthContext,
        client: httpx.AsyncClient,
    ) -> List[AttackResult]:
        """Выполнить атаку и вернуть найденные результаты."""
        raise NotImplementedError
