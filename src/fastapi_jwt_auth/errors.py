__all__ = ["FastAPIJWTAuthError", "JWTEncodeError", "JWTDecodeError"]

from typing_extensions import Annotated, Doc


class FastAPIJWTAuthError(Exception):
    """Base class for FastAPIJWTAuth exceptions"""

    def __init__(self, detail: Annotated[str, Doc("""Error message to pass to the client""")]):
        self.detail = detail


class JWTEncodeError(FastAPIJWTAuthError):
    """Error encoding JWT"""

    def __init__(
        self, detail: Annotated[str, Doc("""Error message to pass to the client""")] = "Error while encoding JWT"
    ):
        super().__init__(detail)


class JWTDecodeError(FastAPIJWTAuthError):
    """Error decoding JWT"""

    def __init__(
        self, detail: Annotated[str, Doc("""Error message to pass to the client""")] = "Error while decoding JWT"
    ):
        super().__init__(detail)
