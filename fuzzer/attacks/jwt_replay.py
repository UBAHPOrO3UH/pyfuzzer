from __future__ import annotations

import json
from typing import List

import httpx

from fuzzer.attacks.base import AttackStrategy, AttackResult
from fuzzer.runners.storage import Endpoint, AuthContext


class JwtReplay(AttackStrategy):
    name = "jwt_replay"

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

        # === Правильно собранный URL ===
        # ctx.base_url гарантированно есть, endpoint.path всегда начинается с /
        if hasattr(ctx, "base_url"):
            url = ctx.base_url.rstrip("/") + endpoint.path
        else:
            # запасной вариант
            url = endpoint.path

        for token in ctx.jwt_tokens:

            headers = dict(endpoint.headers or {})
            headers["Authorization"] = f"Bearer {token}"

            FORBIDDEN = {"content-length", "transfer-encoding", "host", "connection"}
            headers = {k: v for k, v in headers.items() if k.lower() not in FORBIDDEN}

            # === обработка тела ===
            body = endpoint.body
            content = None

            if body not in (None, "", {}):
                if isinstance(body, (dict, list)):
                    content = json.dumps(body)
                elif isinstance(body, bytes):
                    content = body
                else:
                    content = str(body)

            try:
                resp = await client.request(
                    endpoint.method,
                    url,
                    headers=headers,
                    content=content
                )
            except Exception as exc:
                return []  # в атаке ошибка — просто не фиксируем

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
