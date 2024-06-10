# FastAPI JWT Auth [![codecov](https://codecov.io/github/tistaharahap/fastapi-jwt-auth/graph/badge.svg?token=7UHRBSW1ZX)](https://codecov.io/github/tistaharahap/fastapi-jwt-auth)

FastAPI JWT Auth is a lightweight library designed to simplify the integration of JWT authentication into FastAPI applications. By strictly adhering to FastAPI conventions, it provides a seamless and straightforward authentication setup process. The library aims for 100% test coverage.

## Installing

```bash
pip install fastapi-jwt-auth3
```

**NOTE:** There are others who have written similar libraries with identical names. As an homage to the libraries that came before, I have decided to name this library `fastapi-jwt-auth3`.

## How To Use

This is an example single file implementation, let's name it `example.py`.

In order for this example to run, I took the liberty to use the `Faker` library to generate fake data. You can install it by running `pip install faker`.

```python
__all__ = ["app"]

import uuid

from fastapi import FastAPI, Depends, HTTPException

from faker import Faker
from jwcrypto import jwk
from pydantic import BaseModel, ConfigDict, EmailStr
from fastapi_jwt_auth3.jwtauth import FastAPIJWTAuth, KeypairGenerator, JWTPresetClaims, generate_jwt_token

# Initialize the Faker instance to generate fake data
fake = Faker()


# Define the token claims to be projected to when decoding JWT tokens
class TokenClaims(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    email: EmailStr
    iss: str
    aud: str
    exp: int
    sub: str
    iat: int
    jti: str


# Payload for our logins
class LoginIn(BaseModel):
    username: str
    password: str


app = FastAPI(title="FastAPI JWT Auth Example")

# For the purpose of this example, we will generate a new RSA keypair
private_key, public_key = KeypairGenerator.generate_rsa_keypair()

# Create a JWK key from the public key
jwk_key = jwk.JWK.from_pem(public_key.encode("utf-8"))
public_key_id = jwk_key.get("kid")

"""
    Initialize the FastAPIJWTAuth instance with an RSA algorithm. We need to provide a set of private and public key.
"""
jwt_auth = FastAPIJWTAuth(
    algorithm="RS256",
    base_url="http://localhost:8000",
    secret_key=private_key,
    public_key=public_key,
    public_key_id=public_key_id,
    issuer="https://localhost:8000",
    audience="https://localhost:8000",
    expiry=60 * 15,
    refresh_token_expiry=60 * 60 * 24 * 7,
    leeway=0,
    project_to=TokenClaims,
)

"""
    Initialize the FastAPIJWTAuth instance with a FastAPI app. This will add a route at:
    
    [GET] /.well-known/jwks.json
    
    This route will return the public key in JWK format for consumers to verify the JWT token.
"""
jwt_auth.init_app(app)


@app.get("/protected")
async def protected_route(claims: TokenClaims = Depends(jwt_auth)):
    return {"message": f"Hello, {claims.name}!"}


@app.post("/login")
async def login(payload: LoginIn):
    if payload.username != "username" or payload.password != "password":
        raise HTTPException(status_code=401, detail="Invalid credentials")

    preset_claims = JWTPresetClaims.factory(
        issuer=jwt_auth.issuer, audience=jwt_auth.audience, expiry=jwt_auth.expiry, subject=str(uuid.uuid4())
    )
    claims = {"name": fake.name(), "email": fake.email()}
    token = generate_jwt_token(
        header=jwt_auth.header, secret_key=jwt_auth.secret_key, preset_claims=preset_claims, claims=claims
    )
    
    # This is optional but good practice
    refresh_token = jwt_auth.generate_refresh_token(access_token=token)
    
    return {"access_token": token, "refresh_token": refresh_token}
```

We can run the example above with `uvicorn`. You can install with `pip install uvicorn`.

```bash
uvicorn example:app --reload
```

### Handling Refresh Tokens

As you can see in the examples above, you can optionally use a `refresh_token`. What this library does not cover is the handling of the `refresh_token`. You can implement your own logic to handle the refresh token. In terms of best practice, it's prudent to set a short expiry time for the `access_token` like 15 minutes and a longer expiry time for the `refresh_token` like 7 days.

Every `refresh_token` issued by the library will have the following claims attributed to it based on the access token. An example is below:

```json
{
  "iss": "https://localhost:8000",
  "aud": "https://localhost:8000",
  "exp": 1719100800,
  "kid": "U790ZCw3aTvd3Z-Nzm5z2CdW7QFjlGk-HchE3EXhfR8",
  "jku": "http://localhost:8000/.well-known/jwks.json",
  "sub": "cbb6aa8b-a602-43fa-a578-76db183e3b2b",
  "access_token_jti": "84db4b73-df2a-4690-802c-3c55247a6631",
  "access_token_iat": 1717933045
}
```

Refresh token claims will always have the `access_token_jti` and `access_token_iat` claims. These claims are used to verify the integrity of the access token. If the access token is revoked, the refresh token will be invalidated when you set it up as such with your own logic.

## Generating Keys

The library comes with a CLI tool called `keygen` to help you create keys for your application.

![Keygen Help](images/keygen-help.gif)

To generate a new RSA keypair, you can run the following command:

```bash
keygen --algorithm=RS256
```

The private/public keys will be saved at the current working directory with the following filenames:

```
private_key.pem
public_key.pem
```

For a list of the available algorithms supported, you can go here:

[https://pyjwt.readthedocs.io/en/stable/algorithms.html](https://pyjwt.readthedocs.io/en/stable/algorithms.html)

## Development

This project uses `rye` to build, test and publish the package. More about `rye` can be found in the link below:

[https://rye.astral.sh/](https://rye.astral.sh/)

Please install `rye` first before continuing.

### Environment Setup

After `rye` is installed and available in your path, you can do the following to set up the environment:

```bash
git clone git@github.com:tistaharahap/fastapi-jwt-auth.git
cd fastapi-jwt-auth
rye sync
````

### Testing

To run the tests, you can use the following command:

```bash
rye run test
```

When the command is run, coverage reports will be generated in these files and directory:

```
htmlcov/
coverage.json
coverage.xml
```

Coverage report can be viewed as an HTML file by opening `htmlcov/index.html` in your browser.

In addition, coverage report is uploaded to `Codecov`, link [here](https://app.codecov.io/gh/tistaharahap/fastapi-jwt-auth). A Github action in the repository uploads the coverage report to `Codecov` automatically after successful tests.

This project aims to have 100% test coverage.
