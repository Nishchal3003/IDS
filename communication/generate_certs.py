"""
generate_certs.py
-----------------
One-time script that generates a self-signed TLS certificate for the
NIDS private communication server.

Run once before starting the server for the first time:

    python -m communication.generate_certs

Output
------
    certs/server.key  ← private key   (NEVER share this / gitignored)
    certs/server.crt  ← public cert   (safe to copy to Python clients)

The certificate includes SAN (Subject Alternative Name) entries for:
  • 127.0.0.1
  • The machine's detected LAN IP (e.g. 192.168.0.102)
  • localhost

This ensures TLS works whether the server is accessed locally or over LAN.

Security note
-------------
This is a self-signed certificate — it provides strong encryption but no
third-party identity verification.  For the private LAN scenario of this
project, this is the correct and appropriate choice.
"""

import datetime
import ipaddress
import sys
from pathlib import Path
from datetime import timezone

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
CERTS_DIR: Path    = PROJECT_ROOT / "certs"

# Import after path setup so the project modules are findable
sys.path.insert(0, str(PROJECT_ROOT))
from communication.utils import get_local_ip


def generate(force: bool = False) -> None:
    """
    Generate ``server.key`` and ``server.crt`` in the ``certs/`` directory.

    Parameters
    ----------
    force : bool
        If ``True``, overwrite existing files.  Defaults to ``False``.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        print(
            "[ERROR] 'cryptography' package is not installed.\n"
            "        Run:  pip install cryptography"
        )
        sys.exit(1)

    key_path: Path  = CERTS_DIR / "server.key"
    cert_path: Path = CERTS_DIR / "server.crt"

    if cert_path.exists() and key_path.exists() and not force:
        print(f"[INFO] Certificates already exist in {CERTS_DIR}")
        print("       Use --force to regenerate.")
        return

    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    local_ip = get_local_ip()
    print(f"[INFO] Detected LAN IP: {local_ip}")

    # ── 1. Generate 2048-bit RSA private key ────────────────────────────
    print("[INFO] Generating 2048-bit RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # ── 2. Build certificate subject / issuer ───────────────────────────
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,          "NIDS-Server"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,    "Intelligent-NIDS"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,         "IN"),
    ])

    # SAN covers localhost, loopback, and the detected LAN IP
    san_addresses = [
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.DNSName("localhost"),
    ]
    try:
        san_addresses.append(
            x509.IPAddress(ipaddress.IPv4Address(local_ip))
        )
    except ValueError:
        pass

    # ── 3. Build and sign the certificate ───────────────────────────────
    print("[INFO] Signing certificate (valid for 365 days)...")
    now = datetime.datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(san_addresses),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # ── 4. Write private key ─────────────────────────────────────────────
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    print(f"[OK]   Private key  -> {key_path}")

    # ── 5. Write certificate ─────────────────────────────────────────────
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[OK]   Certificate  -> {cert_path}")

    print()
    print("=" * 60)
    print("  TLS certificates generated successfully!")
    print()
    print("  For Python clients on OTHER machines:")
    print(f"    Copy  {cert_path}  to their  certs/  folder.")
    print()
    print("  Browser clients need NO certificate — they connect")
    print("  via plain WebSocket on the private LAN.")
    print("=" * 60)


if __name__ == "__main__":
    force = "--force" in sys.argv
    generate(force=force)
