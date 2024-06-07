import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_webserver_auth(client: AsyncClient):
    response = await client.get("/test")

    assert response.status_code == 401

    payload = {
        "username": "username",
        "password": "password",
    }
    response = await client.post("/login", json=payload)

    assert response.status_code == 200

    token_response = response.json()
    access_token = token_response.get("access_token")

    assert access_token is not None

    headers = {"authorization": f"Bearer {access_token}"}
    response = await client.get("/test", headers=headers)

    assert response.status_code == 200

    response = await client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    headers = {"authorization": "Bearer invalid_token"}
    response = await client.get("/test", headers=headers)

    assert response.status_code == 401
