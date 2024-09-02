__all__ = ["JWTHeader", "JWTPresetClaims"]

from datetime import datetime, timedelta
from typing import Literal, Annotated, ClassVar, Set

import pytz
from pydantic import BaseModel, ConfigDict, field_validator, HttpUrl, field_serializer
from typing_extensions import Doc, Union, Optional


class JWTHeader(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
            "HS256",  # Symmetric
            "HS384",  # Symmetric
            "HS512",  # Symmetric
            "ES256",  # Asymmetric
            "ES256K",  # Asymmetric
            "ES384",  # Asymmetric
            "ES512",  # Asymmetric
            "RS256",  # Asymmetric
            "RS384",  # Asymmetric
            "RS512",  # Asymmetric
            "PS256",  # Asymmetric
            "PS384",  # Asymmetric
            "PS512",  # Asymmetric
            "EdDSA",  # Asymmetric
        ],
        Doc("""
            The algorithm used to sign the JWT. We are using PyJWT and these are the supported algorithms. More info:
            https://pyjwt.readthedocs.io/en/stable/algorithms.html
        """),
    ] = "RS256"
    typ: Annotated[
        Optional[Literal["JWT"]],
        Doc("""
            The type of the token. It is always "JWT".
        """),
    ] = "JWT"
    x5t: Annotated[
        Optional[str],
        Doc("""
            The thumbprint of the X.509 certificate that was used to sign the JWT. This is an optional field.
        """),
    ] = None
    x5u: Annotated[
        Optional[HttpUrl],
        Doc("""
            The URL of the X.509 certificate that was used to sign the JWT. This is an optional field.
        """),
    ] = None
    jku: Annotated[
        Optional[HttpUrl],
        Doc("""
            The URL of the JWK set that contains the public key that was used to sign the JWT. This is an optional 
            field for symmetric algorithms but required for asymmetric algorithms.
        """),
    ] = None
    kid: Annotated[
        Optional[str],
        Doc("""
            The key ID of the public key that was used to sign the JWT. This is an optional field for symmetric 
            algorithms but required for asymmetric algorithms.
        """),
    ] = None

    @field_serializer("jku")
    def serialize_jku(self, v: Optional[HttpUrl], _info) -> Optional[str]:
        return str(v) if v else None

    @classmethod
    def factory(
        cls,
        algorithm: str,
        public_key_id: str,
        base_url: HttpUrl,
        x509_url: Optional[HttpUrl] = None,
        x509_thumbprint: Optional[str] = None,
    ) -> "JWTHeader":
        # Python 3.9 does not add the trailing slash to the URL but 3.12 does, normalize the URL.
        jwks_url = f"{str(base_url).rstrip('/')}/.well-known/jwks.json" if base_url else None
        return cls(alg=algorithm, typ="JWT", kid=public_key_id, jku=jwks_url, x5t=x509_url, x5u=x509_thumbprint)


class JWTPresetClaims(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iss: Annotated[
        str,
        Doc("""
            The JWT token issuer, usually the domain or subdomain of your REST API. This is a required field.
        """),
    ]
    aud: Annotated[
        Union[str, None],
        Doc("""
            The JWT token audience, usually the domain or subdomain of the client or the Frontend that consumes the 
            REST API. The consumer can choose to validate against the value of this claim. This is an optional field.
        """),
    ]
    iat: Annotated[
        Optional[int],
        Doc("""
            The time the JWT token was issued in Unix timestamp. This is an optional field but will be populated if not 
            set.
        """),
    ] = None
    exp: Annotated[
        int,
        Doc("""
            The expiration time of the JWT token in Unix timestamp. This is a required field.
        """),
    ]
    nbf: Annotated[
        Optional[int],
        Doc("""
            This claim specifies the minimum time in Unix timestamp that must have passed since the token was issued. 
            In other words, nbf defines the earliest time at which the token can be considered valid. This is an 
            optional field.
        """),
    ] = None
    jti: Annotated[
        Optional[str],
        Doc("""
            A unique identifier for the issued JWT token. This is an optional field but will be populated if not set.
        """),
    ] = None
    sub: Annotated[
        Optional[str],
        Doc("""
            The subject of the JWT token. This claim represents the subject or user being authenticated. A unique 
            identifier of the user is best practice. This is a required field in requests but not required for 
            initialization purposes.
        """),
    ] = None

    @classmethod
    def factory(cls, issuer: str, expiry: int, audience: str, subject: str) -> "JWTPresetClaims":
        aud = str(audience) if audience else None
        exp = datetime.now(tz=pytz.UTC) + timedelta(seconds=expiry)
        return cls(iss=str(issuer), aud=aud, sub=subject, exp=int(exp.timestamp()))

    @field_validator("iss")
    @classmethod
    def check_iss(cls, v: str) -> str:
        return v.rstrip("/")

    @field_validator("aud")
    @classmethod
    def check_aud(cls, v: str) -> str:
        return v.rstrip("/")
