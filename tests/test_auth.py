import uuid
from datetime import datetime, timedelta
from typing import Tuple

import pytest
from pydantic import BaseModel, EmailStr, ConfigDict

from fastapi_jwt_auth3.errors import JWTEncodeError, JWTDecodeError
from fastapi_jwt_auth3.jwtauth import generate_jwt_token, verify_token, generate_jwk_set, FastAPIJWTAuth
from fastapi_jwt_auth3.models import JWTHeader, JWTPresetClaims


class DecodedTokenModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    email: EmailStr
    iss: str
    aud: str
    exp: int
    sub: str
    iat: int
    jti: str


def test_jwt_auth_rsa_algos(rsa_public_private_keypair: Tuple[str, str, str]):
    private_key, public_key, _ = rsa_public_private_keypair
    rsa_algos = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}

    for _algo in rsa_algos:
        header = JWTHeader(
            alg=_algo,
            typ="JWT",
            kid="test",
            jku="https://example.com/jwks",
        )
        expiry = int((datetime.now() + timedelta(days=1)).timestamp())
        preset_claims = JWTPresetClaims(
            iss="https://example.com",
            aud="https://example.com",
            sub=str(uuid.uuid4()),
            exp=expiry,
        )
        claims = {
            "name": "Batista Harahap",
            "email": "batista@bango29.com",
        }

        token = generate_jwt_token(header=header, preset_claims=preset_claims, secret_key=private_key, claims=claims)

        assert isinstance(token, str)

        verified = verify_token(
            token=token,
            key=public_key,
            algorithm=header.alg,
            audience=preset_claims.aud,
            issuer=preset_claims.iss,
            leeway=0,
        )

        assert verified.get("name") == claims.get("name")
        assert verified.get("email") == claims.get("email")
        assert verified.get("sub") == preset_claims.sub
        assert verified.get("iss") == preset_claims.iss
        assert verified.get("aud") == preset_claims.aud
        assert verified.get("exp") == expiry
        assert verified.get("iat") is not None
        assert verified.get("jti") is not None

        headers = FastAPIJWTAuth.get_unverified_header(token=token)

        assert headers.get("kid") is not None
        assert headers.get("kid") == header.kid


def test_jwt_auth_with_predefined_projection(rsa_public_private_keypair: Tuple[str, str, str]):
    private_key, public_key, _ = rsa_public_private_keypair
    rsa_algos = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}

    for _algo in rsa_algos:
        header = JWTHeader(
            alg=_algo,
            typ="JWT",
            kid="test",
            jku="https://example.com/jwks",
        )
        expiry = int((datetime.now() + timedelta(days=1)).timestamp())
        preset_claims = JWTPresetClaims(
            iss="https://example.com",
            aud="https://example.com",
            sub=str(uuid.uuid4()),
            exp=expiry,
        )
        claims = {
            "name": "Batista Harahap",
            "email": "batista@bango29.com",
        }

        token = generate_jwt_token(header=header, preset_claims=preset_claims, secret_key=private_key, claims=claims)

        assert isinstance(token, str)

        verified = verify_token(
            token=token,
            key=public_key,
            algorithm=header.alg,
            audience=preset_claims.aud,
            issuer=preset_claims.iss,
            leeway=0,
            project_to=DecodedTokenModel,
        )

        assert verified.name == claims.get("name")
        assert verified.email == claims.get("email")
        assert verified.sub == preset_claims.sub
        assert verified.iss == preset_claims.iss
        assert verified.aud == preset_claims.aud
        assert verified.exp == expiry
        assert verified.iat is not None
        assert verified.jti is not None

        headers = FastAPIJWTAuth.get_unverified_header(token=token)

        assert headers.get("kid") is not None
        assert headers.get("kid") == header.kid


def test_jwt_auth_hmac(jwt_secret_key: str):
    hmac_algos = {"HS256", "HS384", "HS512"}

    for _algo in hmac_algos:
        header = JWTHeader(
            alg=_algo,
            typ="JWT",
            kid="test",
        )
        expiry = int((datetime.now() + timedelta(days=1)).timestamp())
        preset_claims = JWTPresetClaims(
            iss="https://example.com",
            aud="https://example.com",
            sub=str(uuid.uuid4()),
            exp=expiry,
        )
        claims = {
            "name": "Batista Harahap",
            "email": "batista@bango29.com",
        }

        token = generate_jwt_token(header=header, preset_claims=preset_claims, secret_key=jwt_secret_key, claims=claims)

        assert isinstance(token, str)

        verified = verify_token(
            token=token,
            key=jwt_secret_key,
            algorithm=header.alg,
            audience=preset_claims.aud,
            issuer=preset_claims.iss,
            leeway=0,
        )

        assert verified.get("name") == claims.get("name")
        assert verified.get("email") == claims.get("email")
        assert verified.get("sub") == preset_claims.sub
        assert verified.get("iss") == preset_claims.iss
        assert verified.get("aud") == preset_claims.aud
        assert verified.get("exp") == expiry
        assert verified.get("iat") is not None
        assert verified.get("jti") is not None

        headers = FastAPIJWTAuth.get_unverified_header(token=token)

        assert headers.get("kid") is not None
        assert headers.get("kid") == header.kid


def test_jwt_auth_ecdsa_algos(
    ecdsa_public_private_keypair: Tuple[str, str], es256k_public_private_keypair: Tuple[str, str]
):
    private_key, public_key = ecdsa_public_private_keypair
    ec_algos = {"ES256", "ES384", "ES512"}

    for _algo in ec_algos:
        header = JWTHeader(
            alg=_algo,
            typ="JWT",
            kid="test",
            jku="https://example.com/jwks",
        )
        expiry = int((datetime.now() + timedelta(days=1)).timestamp())
        preset_claims = JWTPresetClaims(
            iss="https://example.com",
            aud="https://example.com",
            sub=str(uuid.uuid4()),
            exp=expiry,
        )
        claims = {
            "name": "Batista Harahap",
            "email": "batista@bango29.com",
        }

        token = generate_jwt_token(header=header, preset_claims=preset_claims, secret_key=private_key, claims=claims)

        assert isinstance(token, str)

        verified = verify_token(
            token=token,
            key=public_key,
            algorithm=header.alg,
            audience=preset_claims.aud,
            issuer=preset_claims.iss,
            leeway=0,
        )

        assert verified.get("name") == claims.get("name")
        assert verified.get("email") == claims.get("email")
        assert verified.get("sub") == preset_claims.sub
        assert verified.get("iss") == preset_claims.iss
        assert verified.get("aud") == preset_claims.aud
        assert verified.get("exp") == expiry
        assert verified.get("iat") is not None
        assert verified.get("jti") is not None

        headers = FastAPIJWTAuth.get_unverified_header(token=token)

        assert headers.get("kid") is not None
        assert headers.get("kid") == header.kid

    private_key, public_key = es256k_public_private_keypair

    header = JWTHeader(
        alg="ES256K",
        typ="JWT",
        kid="test",
        jku="https://example.com/jwks",
    )
    expiry = int((datetime.now() + timedelta(days=1)).timestamp())
    preset_claims = JWTPresetClaims(
        iss="https://example.com",
        aud="https://example.com",
        sub=str(uuid.uuid4()),
        exp=expiry,
    )
    claims = {
        "name": "Batista Harahap",
        "email": "batista@bango29.com",
    }

    token = generate_jwt_token(header=header, preset_claims=preset_claims, secret_key=private_key, claims=claims)

    assert isinstance(token, str)

    verified = verify_token(
        token=token,
        key=public_key,
        algorithm=header.alg,
        audience=preset_claims.aud,
        issuer=preset_claims.iss,
        leeway=0,
    )

    assert verified.get("name") == claims.get("name")
    assert verified.get("email") == claims.get("email")
    assert verified.get("sub") == preset_claims.sub
    assert verified.get("iss") == preset_claims.iss
    assert verified.get("aud") == preset_claims.aud
    assert verified.get("exp") == expiry
    assert verified.get("iat") is not None
    assert verified.get("jti") is not None

    headers = FastAPIJWTAuth.get_unverified_header(token=token)

    assert headers.get("kid") is not None
    assert headers.get("kid") == header.kid


def test_jwt_auth_eddsa_algo(eddsa_public_private_keypair: Tuple[str, str]):
    private_key, public_key = eddsa_public_private_keypair

    header = JWTHeader(
        alg="EdDSA",
        typ="JWT",
        kid="test",
        jku="https://example.com/jwks",
    )
    expiry = int((datetime.now() + timedelta(days=1)).timestamp())
    preset_claims = JWTPresetClaims(
        iss="https://example.com",
        aud="https://example.com",
        sub=str(uuid.uuid4()),
        exp=expiry,
    )
    claims = {
        "name": "Batista Harahap",
        "email": "batista@bango29.com",
    }

    token = generate_jwt_token(header=header, preset_claims=preset_claims, secret_key=private_key, claims=claims)

    assert isinstance(token, str)

    verified = verify_token(
        token=token,
        key=public_key,
        algorithm=header.alg,
        audience=preset_claims.aud,
        issuer=preset_claims.iss,
        leeway=0,
    )

    assert verified.get("name") == claims.get("name")
    assert verified.get("email") == claims.get("email")
    assert verified.get("sub") == preset_claims.sub
    assert verified.get("iss") == preset_claims.iss
    assert verified.get("aud") == preset_claims.aud
    assert verified.get("exp") == expiry
    assert verified.get("iat") is not None
    assert verified.get("jti") is not None

    headers = FastAPIJWTAuth.get_unverified_header(token=token)

    assert headers.get("kid") is not None
    assert headers.get("kid") == header.kid


def test_encoding_errors(eddsa_public_private_keypair: Tuple[str, str]):
    private_key, public_key = eddsa_public_private_keypair

    header = JWTHeader(
        alg="EdDSA",
        typ="JWT",
        kid="test",
        jku="https://example.com/jwks",
    )
    expiry = int((datetime.now() + timedelta(days=1)).timestamp())
    preset_claims = JWTPresetClaims(
        iss="https://example.com",
        aud="https://example.com",
        sub=str(uuid.uuid4()),
        exp=expiry,
    )
    claims = {"name": "Batista Harahap", "email": "batista@bango29.com"}
    invalid_claims = {"invalid": datetime.now()}

    with pytest.raises(JWTEncodeError):
        generate_jwt_token(header=header, preset_claims=preset_claims, secret_key=private_key, claims=invalid_claims)

    with pytest.raises(JWTEncodeError):
        generate_jwt_token(header=header, preset_claims=preset_claims, secret_key="invalid", claims=claims)


def test_decoding_errors(eddsa_public_private_keypair: Tuple[str, str]):
    private_key, public_key = eddsa_public_private_keypair

    header = JWTHeader(
        alg="EdDSA",
        typ="JWT",
        kid="test",
        jku="https://example.com/jwks",
    )
    expiry = int((datetime.now() + timedelta(days=1)).timestamp())
    preset_claims = JWTPresetClaims(
        iss="https://example.com",
        aud="https://example.com",
        sub=str(uuid.uuid4()),
        exp=expiry,
    )
    claims = {"name": "Batista Harahap", "email": "batista@bango29.com"}

    token = generate_jwt_token(header=header, preset_claims=preset_claims, secret_key=private_key, claims=claims)

    with pytest.raises(JWTDecodeError):
        verify_token(
            token=token,
            key="invalid",
            algorithm=header.alg,
            audience=preset_claims.aud,
            issuer=preset_claims.iss,
            leeway=0,
            project_to=DecodedTokenModel,
        )


def test_generating_jwk_with_empty_list():
    with pytest.raises(ValueError):
        generate_jwk_set(jwt_auths=[])


def test_unverified_header_with_invalid_token():
    with pytest.raises(JWTDecodeError):
        FastAPIJWTAuth.get_unverified_header(token="invalid")
