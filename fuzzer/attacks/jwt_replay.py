from __future__ import annotations

from typing import List

import httpx

from fuzzer.attacks.base import AttackStrategy, AttackResult
from fuzzer.runners.storage import Endpoint, AuthContext


class JwtReplay(AttackStrategy):
    """
    Простая проверка повторного использования JWT.
    Предполагается, что токены в AuthContext.jwt_tokens могут быть "старыми" / повторно используемыми.
    """

    name = "jwt_replay"

    def applicable(self, endpoint: Endpoint, ctx: AuthContext) -> bool:
        if not ctx.jwt_tokens:
            return False
        # считаем, что jwt актуален только для запросов с auth-заголовком
        return endpoint.has_auth_header

    async def run(
        self,
        endpoint: Endpoint,
        ctx: AuthContext,
        client: httpx.AsyncClient,
    ) -> List[AttackResult]:
        results: List[AttackResult] = []

        # здесь предполагается, что endpoint.path содержит полный URL
        url = endpoint.path

        for token in ctx.jwt_tokens:
            headers = dict(ctx.headers)
            headers["Authorization"] = f"Bearer {token}"

            resp = await client.request(
                endpoint.method,
                url,
                headers=headers,
                cookies=ctx.cookies,
                data=ctx.payload,
            )

            # если токен успешно принимается — фиксируем как потенциальную проблему
            if resp.status_code == 200:
                results.append(
                    AttackResult(
                        vulnerability="jwt_replay_possible",
                        endpoint=f"{endpoint.method} {endpoint.path}",
                        severity="high",
                        evidence={
                            "status_code": resp.status_code,
                            "token_prefix": token[:16],
                            "response_sample": resp.text[:512],
                        },
                    )
                )

        return results
