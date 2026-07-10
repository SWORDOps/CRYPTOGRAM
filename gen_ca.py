import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

def create_ca(subject_str, serial, filename):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    attrs = []
    for pair in reversed(subject_str.split(',')):
        k, v = pair.split('=')
        if k == 'CN': oid = NameOID.COMMON_NAME
        elif k == 'OU': oid = NameOID.ORGANIZATIONAL_UNIT_NAME
        elif k == 'O': oid = NameOID.ORGANIZATION_NAME
        elif k == 'C': oid = NameOID.COUNTRY_NAME
        else: continue
        attrs.append(x509.NameAttribute(oid, v))
        
    subject = x509.Name(attrs)
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        serial
    ).not_valid_before(
        datetime.utcnow() - timedelta(days=1)
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(private_key, hashes.SHA256())
    
    with open(f'/fast/MainWorkspace/CRYPTOGRAM/keys/nato/{filename}', 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

create_ca("CN=DND Root CA1-MDN Base AC1,OU=PKI-ICP,OU=DND-MDN,O=GC,C=CA", 0x5CB72AED, "CA_DND_Root_CA1.pem")
create_ca("CN=DND Issuing CA1-MDN Emettrice AC1,OU=PKI-ICP,OU=dnd-mdn,O=gc,C=CA", 0x5CB72B32, "CA_DND_Issuing_CA1.pem")
print("Canadian CA certs created successfully in /keys/nato")
