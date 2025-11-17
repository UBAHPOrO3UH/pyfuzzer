import httpx
from urllib.parse import urljoin

PROXIES = {"http://": "http://127.0.0.1:8083"}

async def run_bwapp(base_url: str):
    login_url = urljoin(base_url, "/login.php")

    async with httpx.AsyncClient(proxies=PROXIES) as client:
        await client.get(login_url)

        data = {
            "login": "bee",
            "password": "bug",
            "security_level": "0",
            "form": "submit"
        }
        await client.post(login_url, data=data)

        # несколько уязвимых модулей
        await client.get(urljoin(base_url, "/xss_relf.php"))
        await client.get(urljoin(base_url, "/csrf_1.php"))

        await client.get(urljoin(base_url, "/logout.php"))
