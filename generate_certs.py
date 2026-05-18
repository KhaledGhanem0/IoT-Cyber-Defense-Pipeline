import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# =============================================================================
# CA Certificate
# =============================================================================

def generate_ca_certificate():
    """Generate the Certificate Authority (CA) certificate and key."""

    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    ca_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Grand Marina Hotel"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Water Systems Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Grand Marina Root CA"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)  # Self-signed: issuer = subject
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return ca_key, ca_cert


# =============================================================================
# Server Certificate
# =============================================================================

def generate_server_certificate(ca_key, ca_cert):
    """Generate the broker server certificate signed by the CA."""

    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    server_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Grand Marina Hotel"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "MQTT Broker"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return server_key, server_cert


# =============================================================================
# Device (Client) Certificate
# =============================================================================

def generate_device_certificate(ca_key, ca_cert, device_number, validity_days=365):
    """
    Generate a client certificate for an IoT sensor device, signed by the CA.

    The Common Name becomes the MQTT username when Mosquitto is configured
    with use_identity_as_username true.

    Args:
        device_number: e.g. "001", "002", "003"
        validity_days: set to a small number to produce an expired cert for testing
    """
    device_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    device_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Grand Marina Hotel"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Water Systems Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"HYDROLOGIC-Device-{device_number}"),
    ])

    not_before = datetime.now(timezone.utc)
    # For the expired test cert we backdate so it is already expired
    if validity_days <= 0:
        not_before = datetime.now(timezone.utc) - timedelta(days=abs(validity_days) + 1)
        not_after = datetime.now(timezone.utc) - timedelta(days=1)
    else:
        not_after = not_before + timedelta(days=validity_days)

    device_cert = (
        x509.CertificateBuilder()
        .subject_name(device_name)
        .issuer_name(ca_cert.subject)
        .public_key(device_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return device_key, device_cert


# =============================================================================
# Rogue CA + Device (for attack/test scenarios)
# =============================================================================

def generate_rogue_ca_and_device():
    """
    Generate a rogue CA and a device cert signed by it.

    Used to test that the broker correctly rejects devices whose certificate
    was not signed by the real Grand Marina CA.
    """
    # Rogue CA
    rogue_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue_ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Rogue Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Root CA"),
    ])
    rogue_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_ca_name)
        .issuer_name(rogue_ca_name)
        .public_key(rogue_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(rogue_ca_key, hashes.SHA256())
    )

    # Rogue device signed by rogue CA
    rogue_device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue_device_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Rogue Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ROGUE-Device-999"),
    ])
    rogue_device_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_device_name)
        .issuer_name(rogue_ca_cert.subject)
        .public_key(rogue_device_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(rogue_ca_key, hashes.SHA256())
    )

    return rogue_ca_key, rogue_ca_cert, rogue_device_key, rogue_device_cert


# =============================================================================
# Save helpers
# =============================================================================

def _save_cert(path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _save_key(path, key):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))


# =============================================================================
# Save all certificates
# =============================================================================

def save_all_certificates(
    ca_key, ca_cert,
    server_key, server_cert,
    device_certs,           # list of (number, key, cert)
    expired_key, expired_cert,
    rogue_ca_key, rogue_ca_cert,
    rogue_device_key, rogue_device_cert,
    output_dir="certs"
):
    """Save every certificate and key the project needs into output_dir."""
    out = Path(output_dir)
    out.mkdir(exist_ok=True)

    # CA
    _save_cert(out / "ca.pem", ca_cert)
    _save_key(out / "ca-key.pem", ca_key)
    print(f"  Saved ca.pem, ca-key.pem")

    # Server
    _save_cert(out / "server.pem", server_cert)
    _save_key(out / "server-key.pem", server_key)
    print(f"  Saved server.pem, server-key.pem")

    # Enrolled devices
    for number, key, cert in device_certs:
        _save_cert(out / f"device-{number}.pem", cert)
        _save_key(out / f"device-{number}-key.pem", key)
        print(f"  Saved device-{number}.pem, device-{number}-key.pem")

    # Expired device (attack/test scenario)
    _save_cert(out / "expired-device.pem", expired_cert)
    _save_key(out / "expired-device-key.pem", expired_key)
    print(f"  Saved expired-device.pem, expired-device-key.pem")

    # Rogue CA + device (attack/test scenario)
    _save_cert(out / "wrong-ca.pem", rogue_ca_cert)
    _save_key(out / "wrong-ca-key.pem", rogue_ca_key)
    _save_cert(out / "wrong-device.pem", rogue_device_cert)
    _save_key(out / "wrong-device-key.pem", rogue_device_key)
    print(f"  Saved wrong-ca.pem, wrong-device.pem (and keys)")


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    print("=" * 55)
    print("  Hydroficient Certificate Generator")
    print("  Grand Marina Hotel — Water Systems Security PKI")
    print("=" * 55)
    print()

    print("[1/5] Generating CA certificate (10-year root)...")
    ca_key, ca_cert = generate_ca_certificate()

    print("[2/5] Generating broker server certificate...")
    server_key, server_cert = generate_server_certificate(ca_key, ca_cert)

    print("[3/5] Generating enrolled device certificates (001–003)...")
    device_certs = []
    for num in ("001", "002", "003"):
        key, cert = generate_device_certificate(ca_key, ca_cert, num)
        device_certs.append((num, key, cert))

    print("[4/5] Generating expired device certificate (test scenario)...")
    expired_key, expired_cert = generate_device_certificate(
        ca_key, ca_cert, device_number="expired", validity_days=-30
    )

    print("[5/5] Generating rogue CA + device certificate (attack scenario)...")
    rogue_ca_key, rogue_ca_cert, rogue_device_key, rogue_device_cert = generate_rogue_ca_and_device()

    print()
    print("Saving all files to certs/...")
    save_all_certificates(
        ca_key, ca_cert,
        server_key, server_cert,
        device_certs,
        expired_key, expired_cert,
        rogue_ca_key, rogue_ca_cert,
        rogue_device_key, rogue_device_cert,
    )

    print()
    print("=" * 55)
    print("  Done! certs/ now contains:")
    print("    ca.pem / ca-key.pem              (root CA)")
    print("    server.pem / server-key.pem      (broker)")
    print("    device-001..003.pem + keys       (enrolled sensors)")
    print("    expired-device.pem + key         (test: expired cert)")
    print("    wrong-ca.pem / wrong-device.pem  (test: rogue CA)")
    print("=" * 55)
