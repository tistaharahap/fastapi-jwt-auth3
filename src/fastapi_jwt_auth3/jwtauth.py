__all__ = [
    "generate_jwt_token",
    "verify_token",
    "KeypairGenerator",
    "FastAPIJWTAuth",
    "JWKSKey",
    "JWKSKeysOut",
    "generate_jwk_set",
]

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
    return_as_tuple: Annotated[
        Optional[bool],
        Doc("""
            Whether to return as a Tuple or the token string itself. Defaults to False. This is a boolean value.
            The Tuple contains the token string, the header as a dictionary, and the claims as a dictionary.
        """),
    ] = False,
) -> Union[str, Tuple[str, Dict[str, Any], Dict[str, Any]]]:
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
        token = jwt.encode(payload=claims, key=secret_key, headers=header.model_dump())
    except TypeError:
        raise JWTEncodeError("Invalid claims, must be a JSON serializable object")
    except jwt.InvalidKeyError:
        raise JWTEncodeError("Invalid secret key")

    if not return_as_tuple:
        return token

    return token, header.model_dump(), claims


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

    kty: Annotated[
        str,
        Doc("""
            Cryptographic algorithm family. This is a string value.
        """),
    ]
    use: Annotated[
        str,
        Doc("""
            The intended use `sig` is the usual value to represent signature. This is a string value.
        """),
    ]
    kid: Annotated[
        str,
        Doc("""
            The unique identifier of the key. This is a string value.
        """),
    ]
    alg: Annotated[
        str,
        Doc("""
            The algorithm intended for use with the key. This is a string value.
        """),
    ]
    n: Annotated[
        str,
        Doc("""
            The RSA modulus for RSA algorithms. This is a string value.
        """),
    ]
    e: Annotated[
        str,
        Doc("""
            The RSA public exponent for RSA algorithms. This is a string value.
        """),
    ]
    x5c: Annotated[
        Optional[List[str]],
        Doc("""
            The X.509 certificate chain for the key. This is an optional field.
        """),
    ] = None
    x5t: Annotated[
        Optional[str],
        Doc("""
            The thumbprint of the X.509 certificate. This is an optional field.
        """),
    ] = None


class JWKSKeysOut(BaseModel):
    keys: Annotated[
        List[JWKSKey],
        Doc("""
            The list of keys in the JSON Web Key Set. This is a list of `JWKSKey` instances.
        """),
    ]


class FastAPIJWTAuth:
    def __init__(
        self,
        algorithm: Annotated[
            Literal[
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
            Doc("""
                The algorithm to use for signing the JWT token. This is a string value.
            """),
        ],
        base_url: Annotated[
            str,
            Doc("""
                The base URL of the application. This is a string value.
            """),
        ],
        public_key_id: Annotated[
            str,
            Doc("""
                The public key identifier. This is a string value.
            """),
        ],
        issuer: Annotated[
            str,
            Doc("""
                The issuer of the JWT token. This is a string value.
            """),
        ],
        secret_key: Annotated[
            str,
            Doc("""
                The secret key used to sign the JWT token. This is a string value.
            """),
        ],
        audience: Annotated[
            str,
            Doc("""
                The audience of the JWT token. This is a string value.
            """),
        ],
        expiry: Annotated[
            int,
            Doc("""
                The expiry time of the JWT token in seconds. This is an integer value.
            """),
        ] = 0,
        refresh_token_expiry: Annotated[
            int,
            Doc("""
                The expiry time of the refresh token in seconds. This is an integer value.
            """),
        ] = 0,
        leeway: Annotated[
            int,
            Doc("""
                The leeway time in seconds. This is used to counter clock skew. Defaults to 0. This is an integer value.
            """),
        ] = 0,
        public_key: Annotated[
            Optional[str],
            Doc("""
                The public key used to verify the JWT token. This is a string value.
            """),
        ] = None,
        project_to: Annotated[
            Optional[Type[PydanticIsh]],
            Doc("""
                The Pydantic model to project the decoded payload to. This is an optional field.
            """),
        ] = None,
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
        """
        Generate a JSON Web Key Set (JWKS) for the public key. Use this if only a single keypair or key is used. Use
        `generate_jwk_set` if multiple keys are used.

        Returns:
        JWKSKeysOut: The JSON Web Key Set.
        """
        return generate_jwk_set(jwt_auths=[self])

    def generate_refresh_token(self, access_token: str) -> str:
        """
        Generate a refresh token based on an access token.

        Parameters:
        access_token (str): A JWT token.

        Returns:
        str: The refresh token.
        """
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

    def verify_token(
        self, creds: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
    ) -> Union[Dict[str, Any], PydanticIsh]:
        """
        Verify a JWT token.

        Parameters:
        creds (Optional[HTTPAuthorizationCredentials]): The HTTPAuthorizationCredentials instance from FastAPI's
        HTTPBearer.

        Returns:
        Union[Dict[str, Any], PydanticIsh]: The decoded payload of the JWT token as a dictionary or Pydantic model.
        """
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

    @staticmethod
    def get_unverified_header(token: str) -> Dict[str, Any]:
        """
        Get the unverified header of a JWT token.

        Parameters:
        token (str): The JWT token.

        Returns:
        Dict[str, Any]: The unverified header of the JWT token.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise JWTDecodeError(f"Error decoding JWT token: {exc}")

        return header

    def __call__(
        self, creds: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
    ) -> Union[Dict[str, Any], PydanticIsh]:
        """
        Called when the instance is called as a function as a FastAPI dependency. This is used to verify a JWT token.

        Parameters:
        creds (Optional[HTTPAuthorizationCredentials]): The HTTPAuthorizationCredentials instance from FastAPI's
        HTTPBearer.

        Returns:
        Union[Dict[str, Any], PydanticIsh]: The decoded payload of the JWT token as a dictionary or Pydantic model.
        """
        return self.verify_token(creds=creds)


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


def generate_jwk_set(jwt_auths: List[FastAPIJWTAuth]) -> JWKSKeysOut:
    """
    Generate a JSON Web Key Set (JWKS) from a list of FastAPIJWTAuth instances.

    Parameters:
    jwt_auths (Optional[List[FastAPIJWTAuth]]): A list of FastAPIJWTAuth instances.

    Returns:
    JWKSKeysOut: The JSON Web Key Set.
    """
    if len(jwt_auths) == 0:
        raise ValueError("No FastAPIJWTAuth instances provided")

    keys = []
    for jwt_auth in jwt_auths:
        key = jwk.JWK.from_pem(jwt_auth.public_key.encode("utf-8"))
        exported = key.export_public(as_dict=True)
        exported.update({"use": "sig", "alg": jwt_auth.header.alg})
        keys.append(exported)

    return JWKSKeysOut(**{"keys": keys})
