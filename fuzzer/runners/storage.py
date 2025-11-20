from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from fuzzer.models import Endpoint, AuthContext


def _parse_cookie_header(cookie_header: str) -> Dict[str, str]:
    cookies = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def parse_proxy_log(log_path: str | Path = "proxy_log.jsonl") -> Tuple[List[Endpoint], List[AuthContext]]:
    log_path = Path(log_path)
    if not log_path.exists():
        return [], []

    endpoints_map: Dict[tuple, Endpoint] = {}
    cookies_global: Dict[str, str] = {}
    headers_global: Dict[str, str] = {}
    jwt_tokens: set[str] = set()

    with log_path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            try:
                entry = json.loads(line)
            except Exception:
                continue

            # host + path → полный URL
            host = entry.get("host")
            raw_path = entry.get("path") or "/"

            if not host:
                continue  # запись повреждена

            full_url = f"http://{host}{raw_path}"

            # разбираем URL
            parsed = urlparse(full_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path or "/"

            method = entry.get("method", "GET")

            key = (method, base_url, path)

            # создаём Endpoint если его ещё нет
            ep = endpoints_map.get(key)
            if not ep:
                ep = Endpoint(
                    method=method,
                    path=path,
                    base_url=base_url,            # ← FIX
                    headers={},
                    params=entry.get("query") or {},
                    body=None,
                    has_auth_cookie=False,
                    has_auth_header=False,
                )
                endpoints_map[key] = ep

            # заголовки
            req_headers = entry.get("req_headers") or {}
            ep.headers = req_headers

            # тело
            ep.body = entry.get("body") or None

            # флаг авторизации в заголовке
            if "authorization" in {k.lower(): v for k, v in req_headers.items()}:
                ep.has_auth_header = True

            # парсим Cookie
            cookie_header = req_headers.get("Cookie") or req_headers.get("cookie")
            if cookie_header:
                parsed = _parse_cookie_header(cookie_header)
                cookies_global.update(parsed)
                ep.has_auth_cookie = True

            # собираем JWT
            for hk, hv in req_headers.items():
                headers_global[hk] = hv
                if hk.lower() == "authorization" and "bearer " in hv.lower():
                    try:
                        jwt_tokens.add(hv.split()[1])
                    except Exception:
                        pass

    # формируем контекст
    ctx = AuthContext(
        base_url="",  # этот параметр мы не храним глобально
        cookies=cookies_global,
        headers=headers_global,
        jwt_tokens=list(jwt_tokens),
    )

    return list(endpoints_map.values()), [ctx]
