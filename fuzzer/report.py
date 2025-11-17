import json
import time

def write_report(scan_id: str, target: str, base_url: str, issues: list):
    report = {
        "scan_id": scan_id,
        "target": target,
        "base_url": base_url,
        "generated": time.time(),
        "issues": [i.model_dump() for i in issues],
        "total": len(issues),
    }

    with open(f"reports/{scan_id}.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
