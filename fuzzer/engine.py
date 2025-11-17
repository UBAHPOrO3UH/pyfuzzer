import httpx

from fuzzer.runners import RUNNERS
from fuzzer.runners.storage import parse_proxy_log
from fuzzer.report import write_report
from fuzzer.attacks.jwt_role_escalation import JwtRoleEscalation
from fuzzer.attacks.jwt_replay import JwtReplay
from fuzzer.attacks.session_fixation import SessionFixation


ATTACKS = [
    JwtRoleEscalation(),
    JwtReplay(),
    SessionFixation(),
]


async def run_scan(scan_id: str, target: str, base_url: str):
    # 1. выполнить сценарий
    await RUNNERS[target](base_url)

    # 2. прочитать перехваченные логи
    endpoints, contexts = parse_proxy_log()

    # 3. выполнить атаки
    issues = []

    PROXY = "http://127.0.0.1:8083"

    async with httpx.AsyncClient(proxy=PROXY, verify=False) as client:
        for ep in endpoints:
            for ctx in contexts:
                for attack in ATTACKS:
                    if attack.applicable(ep, ctx):
                        results = await attack.run(ep, ctx, client)
                        issues.extend(results)

    # 4. записать отчёт
    write_report(scan_id, target, base_url, issues)
