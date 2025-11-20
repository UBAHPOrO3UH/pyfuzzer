import httpx
import logging
from fuzzer.runners import RUNNERS
from fuzzer.runners.storage import parse_proxy_log
from fuzzer.report import write_report
from fuzzer.attacks.jwt_role_escalation import JwtRoleEscalation
from fuzzer.attacks.jwt_replay import JwtReplay
from fuzzer.attacks.session_fixation import SessionFixation

log = logging.getLogger("fuzzer")

ATTACKS = [
    JwtRoleEscalation(),
    JwtReplay(),
    SessionFixation(),
]

scan_status = {}


def make_progress_bar(done: int, total: int, length: int = 28) -> str:
    if total == 0:
        total = 1

    filled = int(length * (done / total))
    empty = length - filled
    return f"[{'#' * filled}{'-' * empty}] {done}/{total} ({round(done / total * 100)}%)"


async def run_scan(scan_id: str, target: str, base_url: str):
    scan_status[scan_id] = {
        "status": "running",
        "done": 0,
        "total": 1,
        "progress": 0.0,
    }

    log.info(f"[SCAN {scan_id}] Scenario start for {target} at {base_url}")

    await RUNNERS[target](base_url)

    endpoints, contexts = parse_proxy_log()
    total_work = len(endpoints) * len(contexts) * len(ATTACKS)
    scan_status[scan_id]["total"] = max(1, total_work)

    log.info(f"[SCAN {scan_id}] Parsed {len(endpoints)} endpoints, "
             f"{len(contexts)} contexts → {total_work} tasks")

    issues = []
    PROXY = "http://127.0.0.1:8083"

    async with httpx.AsyncClient(proxy=PROXY, verify=False) as client:
        job_counter = 0

        for ep in endpoints:
            for ctx in contexts:
                for attack in ATTACKS:
                    job_counter += 1

                    scan_status[scan_id]["done"] = job_counter
                    scan_status[scan_id]["progress"] = job_counter / total_work

                    bar = make_progress_bar(job_counter, total_work)

                    log.info(
                        f"[SCAN {scan_id}] {bar} | "
                        f"{attack.__class__.__name__} -> {ep.method} {ep.path}"
                    )

                    if attack.applicable(ep, ctx):
                        try:
                            results = await attack.run(ep, ctx, client)
                            issues.extend(results)
                        except Exception as exc:
                            log.warning(
                                f"[SCAN {scan_id}] ERROR in {attack.__class__.__name__}: {exc}"
                            )

    write_report(scan_id, target, base_url, issues)

    scan_status[scan_id]["status"] = "finished"
    scan_status[scan_id]["progress"] = 1.0

    log.info(f"[SCAN {scan_id}] Scan complete. Issues: {len(issues)}")
