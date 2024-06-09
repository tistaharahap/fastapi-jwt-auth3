from pathlib import Path

from typer.testing import CliRunner

from fastapi_jwt_auth3.cli import app


def test_keygen_cli():
    rsa_algos = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
    hmac_algos = {"HS256", "HS384", "HS512"}
    es256k_algos = {"ES256K"}
    ec_algos = {"ES256", "ES384", "ES512"}
    eddsa_algos = {"EdDSA"}

    for algo in rsa_algos.union(es256k_algos, ec_algos, eddsa_algos):
        result = CliRunner().invoke(app, ["--algorithm", algo])

        assert result.exit_code == 0

        private_key = Path("./private_key.pem")
        public_key = Path("./public_key.pem")

        assert private_key.exists()
        assert public_key.exists()

        private_key.unlink()
        public_key.unlink()

        result = CliRunner().invoke(app, ["--algorithm", algo, "--print-keys"])

        assert result.exit_code == 0

        private_key = Path("./private_key.pem")
        public_key = Path("./public_key.pem")

        assert not private_key.exists()
        assert not public_key.exists()

    for algo in hmac_algos:
        result = CliRunner().invoke(app, ["--algorithm", algo])

        assert result.exit_code == 0

        private_key = Path("./secret_key.txt")

        assert private_key.exists()

        private_key.unlink()

        result = CliRunner().invoke(app, ["--algorithm", algo, "--print-keys"])

        assert result.exit_code == 0

        private_key = Path("./secret_key.txt")

        assert not private_key.exists()

    result = CliRunner().invoke(app, ["--algorithm", "invalid"])

    assert result.exit_code != 0
