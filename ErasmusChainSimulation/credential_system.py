#!/usr/bin/env python3
"""
Academic Credential System
Integrates Merkle Trees, Digital Signatures, and Certificate Verification
"""

import json
import datetime
import os
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Import our custom modules
from merkle_credentials import MerkleCredentialTree, MerkleProof
from wallet import StudentWallet, AcademicCredential, StudentInfo

# Directory certificati 
CA_DIRECTORY = rf"C:\Users\maruo\Desktop\Group41_ProjectWork_APS"


@dataclass
class VerifiableCredential:
    """Credenziale verificabile con Merkle Tree"""
    credential_id: str
    issuer_university: str
    issued_date: str
    student_info: StudentInfo
    academic_data: Dict[str, Any]
    merkle_root: str
    merkle_tree_info: Dict[str, Any]
    digital_signature: str
    issuer_certificate: str  # Certificato X.509 dell'università emittente


@dataclass
class SelectivePresentation:
    """Presentazione selettiva di credenziali"""
    presentation_id: str
    original_credential_id: str
    presented_fields: List[str]
    merkle_proofs: List[Dict[str, Any]]  # Serialized MerkleProof objects
    merkle_root: str
    presentation_date: str
    target_university: str


class UniversityCredentialManager:
    """
    Manager per le operazioni crittografiche delle università
    Gestisce emissione, firma e verifica delle credenziali
    """
    
    def __init__(self, university_name: str, ca_dir: str = None):
        """
        Inizializza il manager per un'università
        
        Args:
            university_name: "salerno" o "rennes"
            ca_dir: Directory contenente i certificati
        """
        self.university_name = university_name
        
        if ca_dir is None:
            ca_dir = CA_DIRECTORY

        self.ca_dir = Path(ca_dir)
        
        # Carica chiave privata e certificato
        self._load_university_credentials()
        
    def _load_university_credentials(self):
        """Carica chiave privata e certificato dell'università"""
        try:
            # Percorsi dei file
            key_path = self.ca_dir / self.university_name / "private" / f"{self.university_name}-ca.key.pem"
            cert_path = self.ca_dir / self.university_name / "certs" / f"{self.university_name}-ca.cert.pem"
            
            # Carica chiave privata
            with open(key_path, 'rb') as f:
                self.private_key = load_pem_private_key(f.read(), password=None)
            
            # Carica certificato
            with open(cert_path, 'rb') as f:
                self.certificate = x509.load_pem_x509_certificate(f.read())
                
            print(f"Credenziali caricate di {self.university_name}")
            
        except Exception as e:
            print(f"Errore caricamento credenziali di {self.university_name}: {e}")
            raise
    
    def sign_data(self, data: str) -> str:
        """
        Firma dati usando RSA-PSS come specificato nel WP2
        """
        import base64
        
        # RSA-PSS padding come specificato nel WP2
        signature = self.private_key.sign(
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, data: str, signature: str, public_key) -> bool:
        """
        Verifica firma RSA-PSS
        """
        import base64
        
        try:
            signature_bytes = base64.b64decode(signature)
            
            public_key.verify(
                signature_bytes,
                data.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Verifica della firma fallita: {e}")
            return False
    
    def issue_credential(self, student_info: StudentInfo, academic_data: Dict[str, Any]) -> VerifiableCredential:
        """
        Emette una credenziale verificabile (per università ospitante)
        """
        print(f"\n{self.university_name.upper()}: ISSUING CREDENTIAL")
        print("=" * 50)
        
        # 1. Genera ID credenziale
        credential_id = f"{self.university_name.upper()}_CRED_{student_info.student_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # 2. Costruisci Merkle Tree
        merkle_tree = MerkleCredentialTree()
        merkle_root = merkle_tree.build_tree(academic_data)
        
        # 3. Prepara dati da firmare
        credential_data = {
            "credential_id": credential_id,
            "issuer_university": self.university_name,
            "issued_date": datetime.datetime.now().isoformat(),
            "student_info": asdict(student_info),
            "merkle_root": merkle_root,
            "academic_data_hash": merkle_tree.hash_data(json.dumps(academic_data, sort_keys=True))
        }
        
        # 4. Firma digitale
        data_to_sign = json.dumps(credential_data, sort_keys=True)
        digital_signature = self.sign_data(data_to_sign)
        
        # 5. Crea credenziale verificabile
        verifiable_credential = VerifiableCredential(
            credential_id=credential_id,
            issuer_university=self.university_name,
            issued_date=credential_data["issued_date"],
            student_info=student_info,
            academic_data=academic_data,
            merkle_root=merkle_root,
            merkle_tree_info=merkle_tree.get_tree_info(),
            digital_signature=digital_signature,
            issuer_certificate=self.certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        )
        
        print(f"Credenziali emesse con successo")
        print(f"   ID: {credential_id}")
        print(f"   Merkle Root: {merkle_root}")
        print(f"   Campi: {len(merkle_tree.get_tree_info()['fields'])}")
        
        return verifiable_credential
    
    def verify_credential(self, credential: VerifiableCredential) -> bool:
        """
        Verifica una credenziale (per università di origine)
        """
        print(f"\n{self.university_name.upper()}: VERIFICA CREDENZIALI")
        print("=" * 50)
        
        try:
            # 1. Verifica certificato dell'emittente
            issuer_cert = x509.load_pem_x509_certificate(credential.issuer_certificate.encode('utf-8'))
            
            # TODO: In un sistema reale, qui verificheremmo contro la CA root
            # Per ora assumiamo che il certificato sia valido
            print("Certificato valido")
            
            # 2. Verifica firma digitale
            print("Verifica firma digitale")
            credential_data = {
                "credential_id": credential.credential_id,
                "issuer_university": credential.issuer_university,
                "issued_date": credential.issued_date,
                "student_info": asdict(credential.student_info),
                "merkle_root": credential.merkle_root,
                "academic_data_hash": MerkleCredentialTree().hash_data(json.dumps(credential.academic_data, sort_keys=True))
            }
            
            data_to_verify = json.dumps(credential_data, sort_keys=True)
            signature_valid = self.verify_signature(
                data_to_verify, 
                credential.digital_signature, 
                issuer_cert.public_key()
            )
            
            if not signature_valid:
                print("Firma digitale non valida")
                return False
                
            print("Firma digitale valida")
            
            # 3. Verifica Merkle Tree
            tree = MerkleCredentialTree()
            computed_root = tree.build_tree(credential.academic_data)
            
            if computed_root != credential.merkle_root:
                print(f"Merkle root mismatch: {computed_root} != {credential.merkle_root}")
                return False
                
            print("Merkle Tree consistent")
            
            print("Credenziali verificate con successo")
            return True
            
        except Exception as e:
            print(f"Verifica delle credenziali fallita: {e}")
            return False
    
    def verify_selective_presentation(self, presentation: SelectivePresentation) -> bool:
        """
        Verifica una presentazione selettiva
        """
        print(f"\n{self.university_name.upper()}: VERIFICA PRESENTAZIONE SELETTIVA")
        print("=" * 60)
        
        try:
            # Crea un Merkle Tree temporaneo per la verifica
            tree = MerkleCredentialTree()
            tree.merkle_root = presentation.merkle_root
            
            all_valid = True
            disclosed_data = {}
            
            for proof_data in presentation.merkle_proofs:
                # Ricostruisci MerkleProof dall'oggetto serializzato
                proof = MerkleProof(
                    field_name=proof_data['field_name'],
                    field_value=proof_data['field_value'],
                    field_hash=proof_data['field_hash'],
                    proof_path=proof_data['proof_path'],
                    proof_directions=proof_data['proof_directions'],
                    merkle_root=proof_data['merkle_root']
                )
                
                # Verifica la prova
                is_valid = tree.verify_proof(proof)
                
                if is_valid:
                    disclosed_data[proof.field_name] = proof.field_value
                    print(f"  {proof.field_name}: Valid")
                else:
                    print(f"  {proof.field_name}: Invalid")
                    all_valid = False
            
            if all_valid:
                print(f"\nProofs verificate con successo")
                print(f"Informazioni divulgate:")
                for field_name, field_value in disclosed_data.items():
                    if field_name.startswith('exam_'):
                        exam = field_value
                        print(f"  • {exam['course_name']}: {exam['grade']} ({exam['ects_credits']} ECTS)")
                    else:
                        print(f"  • {field_name}: {field_value}")
                        
                return True
            else:
                print(f"Alcune proof non hanno superato la verifica")
                return False
                
        except Exception as e:
            print(f"Presentazione selettiva fallita: {e}")
            return False


class ErasmusCredentialSystem:
    """
    Sistema completo per la gestione delle credenziali Erasmus
    Coordina Rennes (emittente) e Salerno (verificatore)
    """
    
    def __init__(self, ca_dir: str = None):
        """Inizializza il sistema"""
        self.rennes_manager = UniversityCredentialManager("rennes", ca_dir)
        self.salerno_manager = UniversityCredentialManager("salerno", ca_dir)
        
    def create_selective_presentation(self, 
                                    credential: VerifiableCredential,
                                    fields_to_disclose: List[str]) -> SelectivePresentation:
        """
        Crea una presentazione selettiva (dal wallet dello studente)
        """
        print(f"\nCREAZIONE DIVULGAZIONE SELETTIVA DELLO STUDENTE")
        print("=" * 50)
        
        # Ricostruisci Merkle Tree
        tree = MerkleCredentialTree()
        tree.build_tree(credential.academic_data)
        
        # Genera prove per i campi selezionati
        merkle_proofs = []
        for field_name in fields_to_disclose:
            proof = tree.generate_proof(field_name, credential.academic_data)
            if proof:
                # Serializza la prova per il trasporto
                proof_data = {
                    'field_name': proof.field_name,
                    'field_value': proof.field_value,
                    'field_hash': proof.field_hash,
                    'proof_path': proof.proof_path,
                    'proof_directions': proof.proof_directions,
                    'merkle_root': proof.merkle_root
                }
                merkle_proofs.append(proof_data)
                print(f"  Proof generata per: {field_name}")
            else:
                print(f"  Generazione proof fallita per: {field_name}")
        
        presentation = SelectivePresentation(
            presentation_id=f"PRES_{credential.credential_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
            original_credential_id=credential.credential_id,
            presented_fields=fields_to_disclose,
            merkle_proofs=merkle_proofs,
            merkle_root=credential.merkle_root,
            presentation_date=datetime.datetime.now().isoformat(),
            target_university="salerno"
        )
        
        print(f"Presentazione selettiva creata: {presentation.presentation_id}")
        return presentation
    
    def simulate_full_erasmus_flow(self, student_id: str):
        """
        Flusso:
        1. Rennes emette credenziale con Merkle Tree
        2. Studente riceve credenziale nel wallet
        3. Studente crea presentazione selettiva
        4. Salerno verifica presentazione selettiva
        """
        print("FLUSSO DI CREDENZIALICOMPLETO ERASMUS")
        print("=" * 60)
        print("Flusso: Rennes → Student Wallet → Selective Presentation → Salerno")
        print()
        
        try:
            # Dati studente
            student_info = StudentInfo(
                student_id=student_id,
                full_name="Alessandro Maruotto",
                email="a.maruotto1@studenti.unisa.it",
                home_university="salerno"
            )
            
            # Dati accademici da Rennes
            academic_data = {
                "academic_year": "2024-2025",
                "semester": "2° semestre 2024",
                "erasmus_program": True,
                "exams": [
                    {
                        "course_name": "Software Architecture Design",
                        "course_code": "INFO5001",
                        "ects_credits": 6,
                        "grade": "A",
                        "exam_date": "2024-12-15"
                    },
                    {
                        "course_name": "Machine Learning",
                        "course_code": "INFO5002",
                        "ects_credits": 6,
                        "grade": "B+",
                        "exam_date": "2024-11-20"
                    },
                    {
                        "course_name": "Embedded Systems",
                        "course_code": "INFO5003",
                        "ects_credits": 6,
                        "grade": "C",  # Voto che lo studente vuole nascondere
                        "exam_date": "2024-10-30"
                    }
                ],
                "total_ects": 18,
            }
            
            # FASE 1: Rennes emette credenziale verificabile
            print("Fase 1: L'Università di Rennes emette credenziali verificabili")
            verifiable_credential = self.rennes_manager.issue_credential(student_info, academic_data)
            
            # FASE 2: Studente riceve credenziale nel wallet
            print("\nFase 2: Lo studente riceve le credenziali sul suo wallet")
            wallet = StudentWallet(student_id)
            
            # Converti in formato legacy per compatibilità
            legacy_credential = AcademicCredential(
                credential_id=verifiable_credential.credential_id,
                issuer_university=verifiable_credential.issuer_university,
                issued_date=verifiable_credential.issued_date,
                student_info=verifiable_credential.student_info,
                academic_data=verifiable_credential.academic_data,
                digital_signature=verifiable_credential.digital_signature
            )
            
            wallet.receive_credential_from_rennes(legacy_credential)
            
            # FASE 3: Studente crea presentazione selettiva
            print("\nFase 3: Studente crea divulgazione selettiva")
            print("Lo studente decide di nascondere l'esame di Embedded System con voto C")
            
            fields_to_disclose = [
                'academic_year',
                'semester', 
                'total_ects',
                'exam_0',  
                'exam_1',  
                # Nasconde exam_2
            ]
            
            selective_presentation = self.create_selective_presentation(
                verifiable_credential, 
                fields_to_disclose
            )
            
            # FASE 4: Salerno verifica presentazione selettiva
            print("\nFase 4: L'Università di Salerno verifica la presentazione selettiva")
            verification_result = self.salerno_manager.verify_selective_presentation(selective_presentation)
            
            # FASE 5: Risultato finale
            print(f"\nFINAL RESULT")
            print("=" * 30)
            
            if verification_result:
                print("Flusso delle credenziali di Erasmus completato con successo")
                print("\nL'Università di Salerno ha verificato:")
                print("  • Anno e Semestre Accademico")
                print("  • Totali ECTS (18)")
                print("  • Software Architecture Design: Grade A (6 ECTS)")
                print("  • Machine Learning: Grade B+ (6 ECTS)")
                
                print("\nCosa è rimasto privato:")
                print("  • Embedded Systems: Grade C (6 ECTS)")
                
            else:
                print("Verifica credenziali fallita")
                
        except Exception as e:
            print(f"Errore: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    """Esecuzione diretta: demo completo del sistema integrato"""
    print("CREDENTIAL SYSTEM")
    print("=============================")
    print()
    
    import os
    
    ca_dir = CA_DIRECTORY
    
    if not Path(ca_dir).exists():
        print("Certificato non trovato")
        exit(1)
    
    system = ErasmusCredentialSystem()
    system.simulate_full_erasmus_flow("0622702601")
