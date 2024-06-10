__all__ = ["generate_jwt_token", "verify_token", "KeypairGenerator"]

import uuid
from datetime import datetime
from typing import Annotated, Dict, Any, Literal, Iterable, Tuple, TypeVar, Optional, Union, List

import jwt
import pytz
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwcrypto import jwk
from pydantic import BaseModel, ConfigDict
from typing_extensions import Doc, Type

from fastapi_jwt_auth3.errors import JWTEncodeError, JWTDecodeError
from fastapi_jwt_auth3.models import JWTHeader, JWTPresetClaims

PydanticIsh = TypeVar("PydanticIsh", bound=BaseModel)


def generate_jwt_token(
    header: Annotated[
        JWTHeader,
        Doc("""
            The header of the JWT token. This is an instance of the `JWTHeader` class.
        """),
    ],
    preset_claims: Annotated[
        JWTPresetClaims,
        Doc("""
            The preset claims of the JWT token. This is an instance of the `JWTPresetClaims` class.
        """),
    ],
    secret_key: Annotated[
        str,
        Doc("""
            The secret key used to sign the JWT token. For asymmetric algorithms this is the private key portion. This 
            is a string value.
        """),
    ],
    claims: Annotated[
        Optional[Dict[str, Any]],
        Doc("""
            The custom claims of the JWT token. These are additional claims that you want to add to the token.
        """),
    ] = None,
) -> str:
    """
    Generate a JWT token.

    Parameters:
    header (JWTHeader): The header of the JWT token.
    preset_claims (JWTPresetClaims): The preset claims of the JWT token.
    secret_key (str): The secret key used to sign the JWT token.
    claims (Dict[str, Any], optional): The custom claims of the JWT token. Defaults to None.

    Returns:
    str: The JWT token.
    """
    claims = claims if claims is not None else dict()
    claims.update(preset_claims.model_dump(exclude_none=True, exclude_unset=True))

    if not claims.get("iat"):
        claims["iat"] = int(datetime.now(tz=pytz.UTC).timestamp())
    if not claims.get("jti"):
        claims["jti"] = str(uuid.uuid4())

    try:
        token = jwt.encode(payload=claims, key=secret_key, algorithm=header.alg)
    except TypeError:
        raise JWTEncodeError("Invalid claims, must be a JSON serializable object")
    except jwt.InvalidKeyError:
        raise JWTEncodeError("Invalid secret key")

    return token


def verify_token(
    token: Annotated[
        str,
        Doc("""
            The JWT token to verify. This is a string value.
        """),
    ],
    key: Annotated[
        str,
        Doc("""
            For symmetric algorithms, this is the secret key used to sign the JWT token. For asymmetric algorithms, 
            this is the public key portion of the key set. This is a string value.
        """),
    ],
    algorithm: Annotated[
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
            The algorithm used to sign the JWT token. This is a string value.
        """),
    ],
    audience: Annotated[
        Optional[Union[str, Iterable[str]]],
        Doc("""
            The audience claim to verify against. This is an optional field.
        """),
    ] = None,
    issuer: Annotated[
        Optional[Union[str, Iterable[str]]],
        Doc("""
            The issuer claim to verify against. This is an optional field.
        """),
    ] = None,
    leeway: Annotated[
        Optional[int],
        Doc("""
            The leeway time in seconds. This is used to counter clock skew. Defaults to 0. This is an integer value.
        """),
    ] = 0,
    project_to: Annotated[
        Optional[Type[PydanticIsh]],
        Doc("""
            The Pydantic model to project the decoded payload to. This is an optional field.
        """),
    ] = None,
) -> Union[Dict[str, Any], PydanticIsh]:
    """
    Verify a JWT token and returns the decoded payload.

    Parameters:
    token (str): The JWT token to verify.
    key (str): For symmetric algorithms, this is the secret key used to sign the JWT token. For asymmetric algorithms,
        this is the public key portion of the key set.
    algorithm (str): The algorithm used to sign the JWT token.
    audience (str, Iterable[str], optional): The audience claim to verify against. Defaults to None.
    issuer (str, Iterable[str], optional): The issuer claim to verify against. Defaults to None.
    leeway (int, optional): The leeway time in seconds. This is used to counter clock skew. Defaults to 0.
    project_to (Type[BaseModel], optional): The Pydantic model to project the decoded payload to. Defaults to None
        which will return a dictionary.

    Returns:
    Dict | PydanticIsh: The decoded payload of the JWT token.
    """
    try:
        verified = jwt.decode(
            token,
            key,
            verify=True,
            audience=str(audience).rstrip("/"),
            issuer=str(issuer).rstrip("/"),
            leeway=leeway,
            algorithms=[algorithm],
        )
    except jwt.PyJWTError as exc:
        raise JWTDecodeError(f"Error decoding JWT token: {exc}")

    if project_to:
        return project_to(**verified)

    return verified


class JWKSKey(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kty: str
    use: str
    kid: str
    alg: str
    n: str
    e: str
    x5c: Optional[List[str]] = None
    x5t: Optional[str] = None


class JWKSKeysOut(BaseModel):
    keys: List[JWKSKey]


class FastAPIJWTAuth:
    def __init__(
        self,
        algorithm: Literal[
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES256K",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
            "EdDSA",
        ],
        base_url: str,
        public_key_id: str,
        issuer: str,
        secret_key: str,
        audience: str,
        expiry: int = 0,
        refresh_token_expiry: int = 0,
        leeway: int = 0,
        public_key: Optional[str] = None,
        project_to: Optional[Type[PydanticIsh]] = None,
    ):
        self.header = JWTHeader.factory(algorithm=algorithm, base_url=str(base_url), public_key_id=public_key_id)
        self.issuer = str(issuer)
        self.secret_key = secret_key
        self.audience = str(audience)
        self.expiry = expiry
        self.refresh_token_expiry = refresh_token_expiry
        self.leeway = leeway
        self.public_key = public_key
        self.project_to = project_to

    def init_app(self, app: FastAPI):
        self.app = app
        self.add_jwks_route()

    def add_jwks_route(self):
        @self.app.get("/.well-known/jwks.json", response_model=JWKSKeysOut, status_code=200, summary="JSON Web Key Set")
        async def jwks_route():
            return self.jwks

    @property
    def jwks(self) -> JWKSKeysOut:
        key = jwk.JWK.from_pem(self.public_key.encode("utf-8"))
        exported = key.export_public(as_dict=True)
        exported.update({"use": "sig", "alg": self.header.alg})
        return JWKSKeysOut(**{"keys": [exported]})

    def generate_refresh_token(self, access_token: str) -> str:
        verified = verify_token(
            token=access_token,
            key=self.secret_key if self.header.alg in JWTHeader.__symmetric_algos__ else self.public_key,
            algorithm=self.header.alg,
            audience=self.audience,
            issuer=self.issuer,
            leeway=self.leeway,
            project_to=None,
        )
        refresh_token_claims = {"access_token_jti": verified.get("jti"), "access_token_iat": verified.get("iat")}
        refresh_token = generate_jwt_token(
            header=self.header,
            preset_claims=JWTPresetClaims.factory(
                issuer=self.issuer,
                audience=self.audience,
                expiry=self.refresh_token_expiry,
                subject=verified.get("sub"),
            ),
            secret_key=self.secret_key,
            claims=refresh_token_claims,
        )
        return refresh_token

    def __call__(
        self, creds: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
    ) -> Union[Dict[str, Any], PydanticIsh]:
        token = creds.credentials if creds else None
        if not token:
            raise HTTPException(status_code=401, detail="Invalid token")

        is_symmetric = self.header.alg in JWTHeader.__symmetric_algos__
        try:
            verified = verify_token(
                token=token,
                key=self.secret_key if is_symmetric else self.public_key,
                algorithm=self.header.alg,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                project_to=self.project_to,
            )
        except JWTDecodeError:
            raise HTTPException(status_code=401, detail="Invalid token")

        return verified


class KeypairGenerator:
    @classmethod
    def generate_rsa_keypair(cls, public_exponent: int = 65537, key_size: int = 2048) -> Tuple[str, str]:
        """
        Generate an RSA keypair with sane defaults.

        Parameters:
        public_exponent (int): The public exponent to use. Defaults to 65537.
        key_size (int): The key size to use. Defaults to 2048.

        Returns:
        Tuple[str, str]: A tuple containing the private key and public key in PEM format.
        """
        private_key = rsa.generate_private_key(public_exponent=public_exponent, key_size=key_size)
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        public_key = private_key.public_key()
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        return pem_private_key, pem_public_key

    @classmethod
    def generate_ecdsa_keypair(cls, curve: EllipticCurve = ec.SECT233R1()) -> Tuple[str, str]:
        """
        Generate an ECDSA keypair.

        Parameters:
        curve (EllipticCurve): The curve to use. Defaults to SECT233R1.

        Returns:
        Tuple[str, str]: A tuple containing the private key and public key in PEM format.
        """
        private_key = ec.generate_private_key(curve)
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        public_key = private_key.public_key()
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        return pem_private_key, pem_public_key

    @classmethod
    def generate_es256k_keypair(cls) -> Tuple[str, str]:
        """
        Generate an ES256K keypair. An ECDSA keypair using the SECP256K1 curve.

        Returns:
        Tuple[str, str]: A tuple containing the private key and public key in PEM format.
        """
        return cls.generate_ecdsa_keypair(ec.SECP256K1())

    @classmethod
    def generate_eddsa_keypair(cls) -> Tuple[str, str]:
        """
        Generate an EdDSA keypair.

        Returns:
        Tuple[str, str]: A tuple containing the private key and public key in PEM format.
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        public_key = private_key.public_key()
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        return pem_private_key, pem_public_key
