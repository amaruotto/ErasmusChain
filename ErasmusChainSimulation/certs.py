#!/usr/bin/env python3
"""
Root + 2 Intermediate CA 
"""

import os
import datetime
import json
import base64
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption, load_pem_private_key

# Directory certificati 
CA_DIRECTORY = rf"C:\Users\maruo\Desktop\Group41_ProjectWork_APS"


class CertificateGenerator:
    """
    Generatore certificati per Root CA + 2 Intermediate CA
    Con funzionalità di firma digitale RSA-PSS secondo WP2 3.4.2
    """
    
    def __init__(self, ca_dir: str = None):
        """Inizializza il generatore di certificati"""
        if ca_dir is None:
            ca_dir = CA_DIRECTORY  
        
        self.ca_dir = Path(ca_dir)
        self.setup_directories()
        
    def setup_directories(self):
        """Crea la struttura di directory"""
        # Root CA
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        (self.ca_dir / "root").mkdir(exist_ok=True)
        (self.ca_dir / "root" / "certs").mkdir(exist_ok=True)
        (self.ca_dir / "root" / "private").mkdir(exist_ok=True)
        
        # Intermediate CA Salerno
        (self.ca_dir / "salerno").mkdir(exist_ok=True)
        (self.ca_dir / "salerno" / "certs").mkdir(exist_ok=True)
        (self.ca_dir / "salerno" / "private").mkdir(exist_ok=True)
        
        # Intermediate CA Rennes
        (self.ca_dir / "rennes").mkdir(exist_ok=True)
        (self.ca_dir / "rennes" / "certs").mkdir(exist_ok=True)
        (self.ca_dir / "rennes" / "private").mkdir(exist_ok=True)
        
        print(f"Directory creata: {self.ca_dir}")

    def generate_private_key(self, key_size: int = 4096) -> rsa.RSAPrivateKey:
        """Genera chiave privata RSA"""
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    def save_private_key(self, private_key: rsa.RSAPrivateKey, path: Path, password: Optional[str] = None):
        """Salva chiave privata su file"""
        encryption = NoEncryption()
        if password:
            encryption = BestAvailableEncryption(password.encode())
            
        pem_data = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        path.write_bytes(pem_data)
        path.chmod(0o400)
        print(f"Chiave privata salvata: {path}")

    def sign_data_rsa_pss(self, private_key: rsa.RSAPrivateKey, data: str) -> str:
        """
        Firma dati usando RSA-PSS secondo WP2 Section 
        
        Implementa:
        • Salt: valore casuale generato per ogni firma
        • MGF1: Mask Generation Function 
        • SHA-256 per hash function (collision-resistant)
        • PSS padding per prevenire attacchi
        """       
        # RSA-PSS con le specifiche WP2:
        # - Salt: generato automaticamente (MAX_LENGTH per sicurezza massima)
        # - MGF1: Mask Generation Function con SHA-256
        # - Hash: SHA-256 (collision-resistant come richiesto)
        signature = private_key.sign(
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),  # MGF1 con SHA-256
                salt_length=padding.PSS.MAX_LENGTH  # Salt massimo per sicurezza
            ),
            hashes.SHA256()  # Hash function collision-resistant
        )
        
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        print(f"Firma RSA-PSS generata")
        print(f"   Lunghezza della firma: {len(signature)} bytes")
        print(f"   Lunghezza Base64 : {len(signature_b64)} caratteri")
        
        return signature_b64

    def verify_signature_rsa_pss(self, public_key, data: str, signature_b64: str) -> bool:
        """
        Verifica firma RSA-PSS
        
        Verifica le proprietà di sicurezza:
        • Resistenza al No-Message Attack
        • Assenza di Relazioni Moltiplicative  
        • Resistenza alle Collisioni
        """

        try:
            signature = base64.b64decode(signature_b64)
            
            # Verifica RSA-PSS con stessi parametri della firma
            public_key.verify(
                signature,
                data.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            print("Verifica della firma RSA-PSS effettuata con successo")
            return True
            
        except Exception as e:
            print(f"Verifica della firma RSA-PSS fallita: {e}")
            return False

    def load_university_key(self, university_name: str) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Carica chiave privata e certificato di un'università
        """
        try:
            # Percorsi dei file
            key_path = self.ca_dir / university_name / "private" / f"{university_name}-ca.key.pem"
            cert_path = self.ca_dir / university_name / "certs" / f"{university_name}-ca.cert.pem"
            
            # Carica chiave privata (senza password)
            with open(key_path, 'rb') as f:
                private_key = load_pem_private_key(f.read(), password=None)
            
            # Carica certificato
            with open(cert_path, 'rb') as f:
                certificate = x509.load_pem_x509_certificate(f.read())
                
            print(f"Credenziali di Firma dell'Università di{university_name} caricate")
            return private_key, certificate
            
        except Exception as e:
            print(f"Errore caricamento delle credenziali di {university_name} {e}")
            raise

    def create_root_ca(self, 
                      key_password: Optional[str] = None,
                      validity_days: int = 7300) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Crea Root CA
        
        Equivalente OpenSSL:
        openssl genrsa -aes256 -out root/private/root-ca.key.pem 4096
        openssl req -new -x509 -days 7300 -sha256 -extensions v3_ca -key root/private/root-ca.key.pem -out root/certs/root-ca.cert.pem
        """
        print("\n=== CREATECREAZIONE ROOT CA ===")
        
        # Genera chiave privata (4096 bit)
        print("Creating root key (4096 bits)...")
        root_key = self.generate_private_key(key_size=4096)
        
        # Salva chiave privata
        root_key_path = self.ca_dir / "root" / "private" / "root-ca.key.pem"
        self.save_private_key(root_key, root_key_path, key_password)
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "EU"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Academic Network"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Root Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Academic Root CA"),
        ])
        
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(root_key.public_key())
        cert_builder = cert_builder.serial_number(1000)
        cert_builder = cert_builder.not_valid_before(datetime.datetime.utcnow())
        cert_builder = cert_builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
        )
        
        # Estensioni v3_ca
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        
        # Firma certificato
        root_cert = cert_builder.sign(root_key, hashes.SHA256())
        
        # Salva certificato
        root_cert_path = self.ca_dir / "root" / "certs" / "root-ca.cert.pem"
        root_cert_path.write_bytes(root_cert.public_bytes(Encoding.PEM))
        print(f"Root del certificato salvata: {root_cert_path}")
        
        return root_key, root_cert

    def create_intermediate_ca_salerno(self,
                                     root_key: rsa.RSAPrivateKey,
                                     root_cert: x509.Certificate,
                                     key_password: Optional[str] = None,
                                     validity_days: int = 3650) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Crea Intermediate CA per Università di Salerno
        
        Equivalente OpenSSL:
        openssl genrsa -aes256 -out salerno/private/salerno-ca.key.pem 4096
        openssl req -new -sha256 -key salerno/private/salerno-ca.key.pem -out salerno/csr/salerno-ca.csr.pem
        openssl ca -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in salerno/csr/salerno-ca.csr.pem -out salerno/certs/salerno-ca.cert.pem
        """
        print("\n=== CREAZIONE SALERNO INTERMEDIATE CA ===")
        
        # Genera chiave privata (4096 bit)
        salerno_key = self.generate_private_key(key_size=4096)
        
        # Salva chiave privata
        salerno_key_path = self.ca_dir / "salerno" / "private" / "salerno-ca.key.pem"
        self.save_private_key(salerno_key, salerno_key_path, key_password)
        
        # Crea certificato intermediate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Campania"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Salerno"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Università degli Studi di Salerno"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "UNISA Intermediate CA"),
        ])
        
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(root_cert.subject)
        cert_builder = cert_builder.public_key(salerno_key.public_key())
        cert_builder = cert_builder.serial_number(2000)
        cert_builder = cert_builder.not_valid_before(datetime.datetime.utcnow())
        cert_builder = cert_builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
        )
        
        # Estensioni v3_intermediate_ca
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(salerno_key.public_key()),
            critical=False,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        
        # Firma con chiave root
        salerno_cert = cert_builder.sign(root_key, hashes.SHA256())
        
        # Salva certificato
        salerno_cert_path = self.ca_dir / "salerno" / "certs" / "salerno-ca.cert.pem"
        salerno_cert_path.write_bytes(salerno_cert.public_bytes(Encoding.PEM))
        print(f"Certficato dell'Università di Salerno salvato: {salerno_cert_path}")
        
        # Crea certificate chain
        self.create_certificate_chain(root_cert, salerno_cert, "salerno")
        
        return salerno_key, salerno_cert

    def create_intermediate_ca_rennes(self,
                                    root_key: rsa.RSAPrivateKey,
                                    root_cert: x509.Certificate,
                                    key_password: Optional[str] = None,
                                    validity_days: int = 3650) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """
        Crea Intermediate CA per Université de Rennes
        
        Equivalente OpenSSL:
        openssl genrsa -aes256 -out rennes/private/rennes-ca.key.pem 4096
        openssl req -new -sha256 -key rennes/private/rennes-ca.key.pem -out rennes/csr/rennes-ca.csr.pem
        openssl ca -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in rennes/csr/rennes-ca.csr.pem -out rennes/certs/rennes-ca.cert.pem
        """
        print("\n=== CREAZIONE RENNES INTERMEDIATE CA ===")
        
        # Genera chiave privata (4096 bit)
        rennes_key = self.generate_private_key(key_size=4096)
        
        # Salva chiave privata
        rennes_key_path = self.ca_dir / "rennes" / "private" / "rennes-ca.key.pem"
        self.save_private_key(rennes_key, rennes_key_path, key_password)
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bretagne"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Rennes"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Université de Rennes"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Université de Rennes Intermediate CA"),
        ])
        
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(root_cert.subject)
        cert_builder = cert_builder.public_key(rennes_key.public_key())
        cert_builder = cert_builder.serial_number(3000)
        cert_builder = cert_builder.not_valid_before(datetime.datetime.utcnow())
        cert_builder = cert_builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
        )
        
        # Estensioni v3_intermediate_ca
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(rennes_key.public_key()),
            critical=False,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        
        # Firma con chiave root
        rennes_cert = cert_builder.sign(root_key, hashes.SHA256())
        
        # Salva certificato
        rennes_cert_path = self.ca_dir / "rennes" / "certs" / "rennes-ca.cert.pem"
        rennes_cert_path.write_bytes(rennes_cert.public_bytes(Encoding.PEM))
        print(f"Certficato dell'Università di Rennes salvato: {rennes_cert_path}")
        
        # Crea certificate chain
        self.create_certificate_chain(root_cert, rennes_cert, "rennes")
        
        return rennes_key, rennes_cert

    def create_certificate_chain(self, root_cert: x509.Certificate, intermediate_cert: x509.Certificate, ca_name: str):
        """
        Crea certificate chain file
        
        Equivalente: cat {ca_name}/certs/{ca_name}-ca.cert.pem root/certs/root-ca.cert.pem > {ca_name}/certs/{ca_name}-ca-chain.cert.pem
        """
        print(f"Creando {ca_name} certificate chain file...")
        
        chain_path = self.ca_dir / ca_name / "certs" / f"{ca_name}-ca-chain.cert.pem"
        
        # Concatena intermediate + root
        chain_content = (
            intermediate_cert.public_bytes(Encoding.PEM) +
            root_cert.public_bytes(Encoding.PEM)
        )
        
        chain_path.write_bytes(chain_content)
        print(f"{ca_name} certificate chain salvato: {chain_path}")

    def sign_certificate(self,
                        ca_name: str,
                        ca_key: rsa.RSAPrivateKey,
                        ca_cert: x509.Certificate,
                        common_name: str,
                        validity_days: int = 375) -> x509.Certificate:
        """
        Firma un certificato usando una delle CA intermediate
        """
        print(f"\n=== FIRMA CERTIFICATO: {common_name} (CA: {ca_name.upper()}) ===")
        
        # Genera chiave privata (2048 bit per end-entity)
        print(f"Creating key for {common_name} (2048 bits)...")
        cert_key = self.generate_private_key(key_size=2048)
        
        # Salva chiave privata
        safe_name = common_name.replace(".", "-").replace(" ", "-").lower()
        cert_key_path = self.ca_dir / ca_name / "private" / f"{safe_name}.key.pem"
        self.save_private_key(cert_key, cert_key_path)
        
        # Crea certificato
        print(f"Creating certificate for {common_name}...")
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT" if ca_name == "salerno" else "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 
                             "Università degli Studi di Salerno" if ca_name == "salerno" else "Université de Rennes"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(ca_cert.subject)
        cert_builder = cert_builder.public_key(cert_key.public_key())
        cert_builder = cert_builder.serial_number(4000 if ca_name == "salerno" else 5000)
        cert_builder = cert_builder.not_valid_before(datetime.datetime.utcnow())
        cert_builder = cert_builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
        )
        
        # Estensioni per certificati end-entity
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(cert_key.public_key()),
            critical=False,
        )
        
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        
        # Firma certificato
        signed_cert = cert_builder.sign(ca_key, hashes.SHA256())
        
        # Salva certificato
        cert_path = self.ca_dir / ca_name / "certs" / f"{safe_name}.cert.pem"
        cert_path.write_bytes(signed_cert.public_bytes(Encoding.PEM))
        print(f"Certficato salvato: {cert_path}")
        
        return signed_cert


def demo():
    """Demo: crea Root CA + 2 Intermediate CA con test RSA-PSS"""
    print("GENERATORE CERTIFICATO CON RSA-PSS")
    print("=====================================")
    print("Creazione: Root CA + Salerno CA + Rennes CA")
    print("Test: Firma digitale RSA-PSS")
    print()
    
    # Inizializza generatore
    ca = CertificateGenerator()
    
    try:
        # 1. Crea Root CA (senza password)
        root_key, root_cert = ca.create_root_ca()
        
        # 2. Crea Intermediate CA Salerno (senza password)
        salerno_key, salerno_cert = ca.create_intermediate_ca_salerno(root_key, root_cert)
        
        # 3. Crea Intermediate CA Rennes (senza password)
        rennes_key, rennes_cert = ca.create_intermediate_ca_rennes(root_key, root_cert)
        
        print("\nTUTTI I CERTIFICATI SONO STATI CREATI CON SUCCESSO")
        print(f"File salvati in: {ca.ca_dir}")
        
        # 4. Demo RSA-PSS Digital Signatures
        print("\n" + "="*60)
        print("FIRMA DIGITALE RSA-PSS")
        print("="*60)
        
        # Test data per firma
        test_credential_data = {
            "student_id": "0622702601",
            "university": "rennes", 
            "courses": ["Software Architecture Design", "Machine Learning"],
            "issue_date": datetime.datetime.now().isoformat()
        }
        
        data_to_sign = json.dumps(test_credential_data, sort_keys=True)
        print(f"Test credential data: {data_to_sign}")
        
        # Test con Rennes (università ospitante)
        rennes_signature = ca.sign_data_rsa_pss(rennes_key, data_to_sign)
        
        # Verifica con chiave pubblica di Rennes
        rennes_public_key = rennes_cert.public_key()
        verification_result = ca.verify_signature_rsa_pss(rennes_public_key, data_to_sign, rennes_signature)
        
        # Test con Salerno (università di origine)
        salerno_signature = ca.sign_data_rsa_pss(salerno_key, data_to_sign)
        salerno_public_key = salerno_cert.public_key()
        salerno_verification = ca.verify_signature_rsa_pss(salerno_public_key, data_to_sign, salerno_signature)
        
        # Test cross-verification
        cross_verification = ca.verify_signature_rsa_pss(salerno_public_key, data_to_sign, rennes_signature)
        
        print(f"\nRISULTATI DDEL TEST SULLA FIRMA DIGITALE RSA-PSS:")
        print(f"Auto-verifica Rennes: {'SUPERATA' if verification_result else 'FALLITA'}")
        print(f"Auto-verifica Salerno: {'SUPERATA' if salerno_verification else 'FALLITA'}")
        print(f"Cross-verification: {'FALLITA (come atteso)' if not cross_verification else 'SUPERATA IN MODO IMPREVISTO'}")
        
        print("\nFILE GENERATI:")
        print("Root CA:")
        print(f"  {ca.ca_dir}/root/private/root-ca.key.pem")
        print(f"  {ca.ca_dir}/root/certs/root-ca.cert.pem")
        
        print("Salerno CA:")
        print(f"  {ca.ca_dir}/salerno/private/salerno-ca.key.pem")
        print(f"  {ca.ca_dir}/salerno/certs/salerno-ca.cert.pem")
        print(f"  {ca.ca_dir}/salerno/certs/salerno-ca-chain.cert.pem")
        
        print("Rennes CA:")
        print(f"  {ca.ca_dir}/rennes/private/rennes-ca.key.pem")
        print(f"  {ca.ca_dir}/rennes/certs/rennes-ca.cert.pem")
        print(f"  {ca.ca_dir}/rennes/certs/rennes-ca-chain.cert.pem")
        
        if verification_result and salerno_verification and not cross_verification:
            print(f"\nIMPLEMENTAZIONE COMPLETATA CON SUCCESSO")
        else:
            print(f"\nTEST FALLITO")
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    """Esecuzione diretta: demo completo con certificati e RSA-PSS"""
    print("GENERAZIONE CERTIFICATI")
    print("=================")
    print()
    
    # Verifica dipendenze
    try:
        from cryptography import x509
    except ImportError:
        print("'cryptography' library not found!")
        print("Install it with: pip install cryptography")
        exit(1)
    
    # Esegui direttamente la demo completa senza menu
    demo()
