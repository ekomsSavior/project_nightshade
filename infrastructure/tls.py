"""
Nightshade TLS Certificate Manager.
Generates self-signed certificates for HTTPS C2 communication using the
cryptography library. Certs stored in certs/ directory with campaign naming.
"""
import os
import datetime
from typing import Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class TLSCertManager:
    """Manage self-signed TLS certificates for Nightshade C2."""

    def __init__(self, cert_dir: str = ""):
        if not cert_dir:
            self._cert_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "certs")
        else:
            self._cert_dir = cert_dir
        os.makedirs(self._cert_dir, exist_ok=True)

    def generate_self_signed(
        self,
        common_name: str = "nightshade-c2.local",
        campaign_name: str = "default",
        validity_days: int = 365,
        key_size: int = 2048,
    ) -> Tuple[str, str]:
        """Generate a self-signed RSA certificate and key.

        Args:
            common_name: CN for the certificate (typically C2 domain or IP)
            campaign_name: Used in the output filename (campaign_cert.pem, campaign_key.pem)
            validity_days: Certificate validity period
            key_size: RSA key size (2048 or 4096)

        Returns:
            Tuple of (cert_path, key_path)
        """
        # Generate RSA key pair
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )

        # Build subject/issuer (self-signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Nightshade Operations"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "C2 Infrastructure"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(common_name), x509.DNSName("localhost")]
                    + [x509.IPAddress(ip) for ip in self._parse_ips(common_name)]
                ),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    key_agreement=False,
                    content_commitment=False,
                    data_encipherment=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256(), backend=default_backend())
        )

        # Write certificate
        cert_path = os.path.join(self._cert_dir, f"{campaign_name}_cert.pem")
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Write private key
        key_path = os.path.join(self._cert_dir, f"{campaign_name}_key.pem")
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        print(f"  [*] Certificate: {cert_path}")
        print(f"  [*] Private key: {key_path}")
        print(f"  [*] Common Name: {common_name}")
        print(f"  [*] Valid until: {now + datetime.timedelta(days=validity_days)}")

        return cert_path, key_path

    @staticmethod
    def _parse_ips(common_name: str) -> list:
        """Parse IP addresses from common name string."""
        import ipaddress
        ips = []
        for part in common_name.split(","):
            part = part.strip()
            try:
                ips.append(ipaddress.ip_address(part))
            except ValueError:
                continue
        return ips

    def load_cert_and_key(self, campaign_name: str = "default") -> Tuple[Optional[str], Optional[str]]:
        """Get paths for existing cert/key files for a campaign.

        Returns:
            Tuple of (cert_path, key_path) or (None, None) if not found
        """
        cert_path = os.path.join(self._cert_dir, f"{campaign_name}_cert.pem")
        key_path = os.path.join(self._cert_dir, f"{campaign_name}_key.pem")

        if os.path.exists(cert_path) and os.path.exists(key_path):
            return cert_path, key_path
        return None, None

    def list_certificates(self) -> list[dict]:
        """List all generated certificates in the certs directory."""
        certs = []
        if not os.path.exists(self._cert_dir):
            return certs

        for fname in os.listdir(self._cert_dir):
            if fname.endswith("_cert.pem"):
                path = os.path.join(self._cert_dir, fname)
                try:
                    with open(path, "rb") as f:
                        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                    certs.append({
                        "filename": fname,
                        "campaign": fname.replace("_cert.pem", ""),
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "not_before": cert.not_valid_before.isoformat(),
                        "not_after": cert.not_valid_after.isoformat(),
                        "serial": str(cert.serial_number),
                    })
                except Exception:
                    continue
        return certs

    @staticmethod
    def configure_flask(app, cert_path: str, key_path: str):
        """Configure a Flask app to use the generated TLS cert.

        Call app.run(ssl_context=(cert_path, key_path)) instead.
        This method modifies app.config for reference.
        """
        app.config["SSL_CERT_PATH"] = cert_path
        app.config["SSL_KEY_PATH"] = key_path
