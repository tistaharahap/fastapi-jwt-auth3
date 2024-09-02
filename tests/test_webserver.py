from typing import Tuple

import pytest
from httpx import AsyncClient

from fastapi_jwt_auth3.jwtauth import JWKSKeysOut, FastAPIJWTAuth, verify_token


@pytest.mark.asyncio
async def test_webserver_auth(client: AsyncClient, jwt_auth: Tuple[FastAPIJWTAuth, str, str]):
    auth, _, _ = jwt_auth

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
    refresh_token = token_response.get("refresh_token")

    assert access_token is not None
    assert refresh_token is not None

    jwt_headers = auth.get_unverified_header(token=access_token)

    assert jwt_headers.get("alg") == auth.header.alg
    assert jwt_headers.get("typ") == auth.header.typ
    assert jwt_headers.get("kid") == auth.header.kid
    assert jwt_headers.get("jku") == str(auth.header.jku)
    assert jwt_headers.get("jku") == "http://testapi/.well-known/jwks.json"

    verified_access_token = verify_token(
        token=access_token,
        key=auth.secret_key if auth.header.alg in ["HS256", "HS384", "HS512"] else auth.public_key,
        algorithm=auth.header.alg,
        audience=auth.audience,
        issuer=auth.issuer,
        leeway=auth.leeway,
        project_to=None,
    )

    assert verified_access_token.get("iss") == auth.issuer
    assert verified_access_token.get("aud") == auth.audience
    assert verified_access_token.get("sub") is not None
    assert verified_access_token.get("exp") is not None
    assert verified_access_token.get("iat") is not None
    assert verified_access_token.get("jti") is not None
    assert verified_access_token.get("name") is not None
    assert verified_access_token.get("email") is not None

    verified_refresh_token = verify_token(
        token=refresh_token,
        key=auth.secret_key if auth.header.alg in ["HS256", "HS384", "HS512"] else auth.public_key,
        algorithm=auth.header.alg,
        audience=auth.audience,
        issuer=auth.issuer,
        leeway=auth.leeway,
        project_to=None,
    )

    refresh_token_headers = auth.get_unverified_header(token=access_token)

    assert refresh_token_headers.get("alg") == auth.header.alg
    assert refresh_token_headers.get("typ") == auth.header.typ
    assert refresh_token_headers.get("kid") == auth.header.kid
    assert refresh_token_headers.get("jku") == str(auth.header.jku)
    assert refresh_token_headers.get("jku") == "http://testapi/.well-known/jwks.json"

    assert verified_refresh_token.get("iss") == auth.issuer
    assert verified_refresh_token.get("aud") == auth.audience
    assert verified_refresh_token.get("sub") == verified_access_token.get("sub")
    assert verified_refresh_token.get("exp") is not None
    assert verified_refresh_token.get("iat") is not None
    assert verified_refresh_token.get("jti") is not None
    assert verified_refresh_token.get("access_token_jti") == verified_access_token.get("jti")
    assert verified_refresh_token.get("access_token_iat") == verified_access_token.get("iat")

    headers = {"authorization": f"Bearer {access_token}"}
    response = await client.get("/test", headers=headers)

    assert response.status_code == 200

    response = await client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    jwks = JWKSKeysOut(**response.json())

    assert isinstance(jwks.keys, list)
    assert jwks.keys[0].kid == auth.jwks.keys[0].kid

    headers = {"authorization": "Bearer invalid_token"}
    response = await client.get("/test", headers=headers)

    assert response.status_code == 401
