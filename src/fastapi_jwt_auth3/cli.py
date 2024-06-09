from pathlib import Path
from secrets import token_hex
from typing import Optional

import typer
from typing_extensions import Annotated, Doc

from fastapi_jwt_auth3.jwtauth import KeypairGenerator

app = typer.Typer(
    pretty_exceptions_enable=False,
    rich_markup_mode="rich",
)
banner = r"""
 _  __ ________  _ _____ _____ _     
/ |/ //  __/\  \///  __//  __// \  /|
|   / |  \   \  / | |  _|  \  | |\ ||
|   \ |  /_  / /  | |_//|  /_ | | \||
\_|\_\\____\/_/   \____\\____\\_/  \|
                                     
"""


def header():
    typer.echo(banner)


@app.command(
    epilog="Made with [red]:heart:[/red] in [green]Dubai[/green].",
    help="A tool to create private/public keys for JWT signing.",
)
def keygen(
    algorithm: Annotated[
        str,
        Doc(
            """
            The algorithm used to sign the JWT token. This is a string value.
        """
        ),
    ] = typer.Option(..., help="The algorithm used to sign the JWT token."),
    secret_key_path: Annotated[
        Optional[str],
        Doc(
            """
            The path to save the secret key excluding the filename. This is a string value.
        """
        ),
    ] = typer.Option("./", help="The path to save the secret key."),
    public_key_path: Annotated[
        Optional[str],
        Doc(
            """
            The path to save the public key for asymmetric algorithms excluding the filename. This is a string value.
        """
        ),
    ] = typer.Option("./", help="The path to save the public key."),
    print_keys: Annotated[
        bool,
        Doc(
            """
            Print the generated keys to the console. This option will not save keys to files. This is a boolean value.
        """
        ),
    ] = typer.Option(False, allow_dash=True, help="Print the generated keys to the console."),
):
    header()

    typer.echo(f"Algorithm: {algorithm}")

    rsa_algos = [{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}, KeypairGenerator.generate_rsa_keypair]
    hmac_algos = [{"HS256", "HS384", "HS512"}, lambda: token_hex(88)]
    es256k_algos = [{"ES256K"}, KeypairGenerator.generate_es256k_keypair]
    ec_algos = [{"ES256", "ES384", "ES512"}, KeypairGenerator.generate_ecdsa_keypair]
    eddsa_algos = [{"EdDSA"}, KeypairGenerator.generate_eddsa_keypair]

    if algorithm in rsa_algos[0]:
        private_key, public_key = rsa_algos[1]()
    elif algorithm in hmac_algos[0]:
        private_key = hmac_algos[1]()
        public_key = None
    elif algorithm in es256k_algos[0]:
        private_key, public_key = es256k_algos[1]()
    elif algorithm in ec_algos[0]:
        private_key, public_key = ec_algos[1]()
    elif algorithm in eddsa_algos[0]:
        private_key, public_key = eddsa_algos[1]()
    else:
        raise ValueError("Invalid algorithm")

    if not print_keys:
        if secret_key_path:
            fn = "private_key.pem" if algorithm not in hmac_algos[0] else "secret_key.txt"
            typer.echo(f"Secret Key Path: {Path(secret_key_path).resolve()}/{fn}")
            with open(f"{secret_key_path}/{fn}", "w") as f:
                f.write(private_key)
        if public_key_path and public_key:
            fn = "public_key.pem" if algorithm not in hmac_algos[0] else None
            if fn:
                typer.echo(f"Public Key Path: {Path(public_key_path).resolve()}/{fn}")
                with open(f"{public_key_path}/{fn}", "w") as f:
                    f.write(public_key)
        return

    typer.echo(f"\nPrivate Key: \n{private_key}")
    if public_key:
        typer.echo(f"\nPublic Key: \n{public_key}")


if __name__ == "__main__":
    app()  # pragma: no cover
