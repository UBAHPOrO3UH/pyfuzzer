from mitmproxy import http
from urllib.parse import urlparse, parse_qs
import json
import time

LOG_FILE = "proxy_log.jsonl"

class Recorder:
    def __init__(self):
        self.f = open(LOG_FILE, "a", encoding="utf-8")

    def request(self, flow: http.HTTPFlow):
        self._log(flow, "request")

    def response(self, flow: http.HTTPFlow):
        self._log(flow, "response")

    def _log(self, flow: http.HTTPFlow, stage: str):
        try:
            parsed = urlparse(flow.request.url)
            entry = {
                "t": time.time(),
                "stage": stage,
                "method": flow.request.method,
                "host": parsed.hostname,
                "path": parsed.path,
                "query": parse_qs(parsed.query),
                "req_headers": dict(flow.request.headers),
                "req_body": flow.request.get_text(),
                "status": flow.response.status_code if flow.response else None,
                "resp_headers": dict(flow.response.headers) if flow.response else None,
                "resp_body": flow.response.get_text()[:4096] if flow.response else None,
            }
            self.f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self.f.flush()
        except Exception as e:
            print("proxy error:", e)

addons = [Recorder()]