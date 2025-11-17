from __future__ import annotations

from typing import List

import httpx

from fuzzer.attacks.base import AttackStrategy, AttackResult
from fuzzer.runners.storage import Endpoint, AuthContext


SESSION_KEYS = ("phpsessid", "jsessionid", "sessionid", "sid")


class SessionFixation(AttackStrategy):
    """
    Базовая проверка на наличие фиксируемой сессии:
    - есть "сессионные" cookie
    - запрос с этими cookie успешно проходит
    Реальная логика фиксации/перехвата сессии добавляется поверх.
    """

    name = "session_fixation"

    def applicable(self, endpoint: Endpoint, ctx: AuthContext) -> bool:
        if not ctx.cookies:
            return False
        keys = [k.lower() for k in ctx.cookies.keys()]
        return any(any(sk in k for sk in SESSION_KEYS) for k in keys)

    async def run(
        self,
        endpoint: Endpoint,
        ctx: AuthContext,
        client: httpx.AsyncClient,
    ) -> List[AttackResult]:
        results: List[AttackResult] = []
        url = endpoint.path

        session_cookies = {
            k: v
            for k, v in ctx.cookies.items()
            if any(sk in k.lower() for sk in SESSION_KEYS)
        }
        if not session_cookies:
            return results

        # делаем пробный запрос с теми же сессионными cookie
        resp = await client.request(
            endpoint.method,
            url,
            headers=ctx.headers,
            cookies=ctx.cookies,
        )

        if resp.status_code == 200:
            results.append(
                AttackResult(
                    vulnerability="session_fixation_candidate",
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    severity="medium",
                    evidence={
                        "session_cookies": list(session_cookies.keys()),
                        "status_code": resp.status_code,
                        "response_sample": resp.text[:512],
                    },
                )
            )

        return results
