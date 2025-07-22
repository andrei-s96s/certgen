import os
import yaml
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime, timedelta, UTC
import ipaddress

CONFIG_FILE = 'config.yaml'

# Загрузка конфига
def load_config():
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def create_ca(ca_conf):
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, ca_conf.get('country', 'RU')),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_conf.get('organization', 'MyOrg')),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_conf['common_name'])
    ])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=ca_conf.get('validity_days', 3650)))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open('ca.key', 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open('ca.crt', 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert

def load_ca():
    with open('ca.key', 'rb') as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    with open('ca.crt', 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return key, cert

def create_cert(cert_conf, ca_key, ca_cert, pfx_password):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cert_conf['common_name'])
    ])
    alt_names = []
    for dns in cert_conf.get('san_dns', []):
        alt_names.append(x509.DNSName(dns))
    for ip in cert_conf.get('san_ip', []):
        alt_names.append(x509.IPAddress(ipaddress.ip_address(ip)))
    san = x509.SubjectAlternativeName(alt_names) if alt_names else None
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=cert_conf.get('validity_days', 825)))
    )
    if san:
        builder = builder.add_extension(san, critical=False)
    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    fname = cert_conf['common_name'].replace('*', 'star')
    # Только PFX
    pfx = pkcs12.serialize_key_and_certificates(
        name=fname.encode(),
        key=key,
        cert=cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(pfx_password.encode())
    )
    with open(f'{fname}.pfx', 'wb') as f:
        f.write(pfx)
    print(f'Сертификат {fname}.pfx создан.')

def main():
    config = load_config()
    pfx_password = config['ca'].get('pfx_password', 'vpnpass')
    if not (os.path.exists('ca.key') and os.path.exists('ca.crt')):
        ca_key, ca_cert = create_ca(config['ca'])
    else:
        ca_key, ca_cert = load_ca()
    for cert_conf in config['certs']:
        create_cert(cert_conf, ca_key, ca_cert, pfx_password)

if __name__ == '__main__':
    main() 