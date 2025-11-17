import httpx
from urllib.parse import urljoin


async def run_juice_shop(base_url: str):

    async with httpx.AsyncClient(proxy="http://127.0.0.1:8083", verify=False) as client:
        await client.get(base_url)

        # 2. Регистрация (любая почта)
        signup_payload = {
            "email": "test_fuzzer@local",
            "password": "test1234",
        }
        await client.post(urljoin(base_url, "/api/Users"), json=signup_payload)

        # 3. Логин
        login_payload = {
            "email": "test_fuzzer@local",
            "password": "test1234",
        }
        r = await client.post(urljoin(base_url, "/rest/user/login"), json=login_payload)

        jwt = r.json().get("authentication", {}).get("token")
        headers = {"Authorization": f"Bearer {jwt}"} if jwt else {}

        # 4. Несколько защищённых эндпоинтов
        await client.get(urljoin(base_url, "/rest/user/whoami"), headers=headers)
        await client.get(urljoin(base_url, "/rest/orders"), headers=headers)