# src/fastapi_jwt_auth3/models.py
__all__ = ["JWTHeader", "JWTPresetClaims"]

from datetime import datetime, timedelta
from typing import Literal, Annotated, ClassVar, Set

import pytz
from typing_extensions import Doc, Union, Optional
from pydantic import HttpUrl

# Import from our compatibility layer
from fastapi_jwt_auth3.compat import BaseModel, configure_model, PYDANTIC_V2, validator, field_serializer


class JWTHeader(BaseModel):
    # Remove model_config = ConfigDict(extra="forbid")

    __asymmetric_algos__: ClassVar[Set[str]] = {
        "ES256",
        "ES256K",
        "ES384",
        "ES512",
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
    }
    __symmetric_algos__: ClassVar[Set[str]] = {"HS256", "HS384", "HS512"}

    alg: Annotated[
        Literal[
            "HS256",
            "HS384",
            "HS512",
            "ES256",
            "ES256K",
            "ES384",
            "ES512",
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "EdDSA",
        ],
        Doc("""
            The algorithm used to sign the JWT. We are using PyJWT and these are the supported algorithms. More info:
            https://pyjwt.readthedocs.io/en/stable/algorithms.html
        """),
    ] = "RS256"
    typ: Annotated[
        Optional[Literal["JWT"]],
        Doc("""The type of the token. It is always "JWT"."""),
    ] = "JWT"
    x5t: Annotated[
        Optional[str],
        Doc("""The thumbprint of the X.509 certificate that was used to sign the JWT."""),
    ] = None
    x5u: Annotated[
        Optional[HttpUrl],
        Doc("""The URL of the X.509 certificate that was used to sign the JWT."""),
    ] = None
    jku: Annotated[
        Optional[HttpUrl],
        Doc("""The URL of the JWK set that contains the public key that was used to sign the JWT."""),
    ] = None
    kid: Annotated[
        Optional[str],
        Doc("""The key ID of the public key that was used to sign the JWT."""),
    ] = None

    # Different serialization approaches for v1 and v2
    if PYDANTIC_V2:

        @field_serializer("jku")
        def serialize_jku(self, v: Optional[HttpUrl], _info) -> Optional[str]:
            return str(v) if v else None
    else:
        # For v1, use a property
        def dict(self, *args, **kwargs):
            data = super().dict(*args, **kwargs)
            if self.jku:
                data["jku"] = str(self.jku)
            return data

    @classmethod
    def factory(
        cls,
        algorithm: str,
        public_key_id: str,
        base_url: HttpUrl,
        x509_url: Optional[HttpUrl] = None,
        x509_thumbprint: Optional[str] = None,
    ) -> "JWTHeader":
        jwks_url = f"{str(base_url).rstrip('/')}/.well-known/jwks.json" if base_url else None
        return cls(alg=algorithm, typ="JWT", kid=public_key_id, jku=jwks_url, x5t=x509_thumbprint, x5u=x509_url)


# Apply configuration
configure_model(JWTHeader, extra="forbid")


class JWTPresetClaims(BaseModel):
    # Remove model_config = ConfigDict(extra="forbid")

    iss: Annotated[
        str,
        Doc("""The JWT token issuer, usually the domain or subdomain of your REST API."""),
    ]
    aud: Annotated[
        Union[str, None],
        Doc("""The JWT token audience, usually the domain or subdomain of the client."""),
    ]
    iat: Annotated[
        Optional[int],
        Doc("""The time the JWT token was issued in Unix timestamp."""),
    ] = None
    exp: Annotated[
        int,
        Doc("""The expiration time of the JWT token in Unix timestamp."""),
    ]
    nbf: Annotated[
        Optional[int],
        Doc("""The earliest time at which the token can be considered valid."""),
    ] = None
    jti: Annotated[
        Optional[str],
        Doc("""A unique identifier for the issued JWT token."""),
    ] = None
    sub: Annotated[
        Optional[str],
        Doc("""The subject of the JWT token. This claim represents the user being authenticated."""),
    ] = None

    @classmethod
    def factory(cls, issuer: str, expiry: int, audience: str, subject: str) -> "JWTPresetClaims":
        aud = str(audience) if audience else None
        exp = datetime.now(tz=pytz.UTC) + timedelta(seconds=expiry)
        return cls(iss=str(issuer), aud=aud, sub=subject, exp=int(exp.timestamp()))

    # Use compatible validator
    @validator("iss")
    @classmethod
    def check_iss(cls, v: str) -> str:
        return v.rstrip("/")

    @validator("aud")
    @classmethod
    def check_aud(cls, v: str) -> str:
        return v.rstrip("/")


# Apply configuration
configure_model(JWTPresetClaims, extra="forbid")
