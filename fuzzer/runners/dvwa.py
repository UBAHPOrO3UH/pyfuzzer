import httpx
from urllib.parse import urljoin

PROXIES = {"http://": "http://127.0.0.1:8083"}

async def run_dvwa(base_url: str):
    login_page = urljoin(base_url, "/login.php")


    async with httpx.AsyncClient(proxy="http://127.0.0.1:8083", verify=False) as client:
        await client.get(login_page)

        # 2. POST login
        data = {"username": "admin", "password": "password", "Login": "Login"}
        await client.post(login_page, data=data)

        # 3. перейти в модули авторизации
        await client.get(urljoin(base_url, "/vulnerabilities/brute/"))
        await client.get(urljoin(base_url, "/vulnerabilities/csrf/"))

        # 4. logout
        await client.get(urljoin(base_url, "/logout.php"))
