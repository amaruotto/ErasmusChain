"""
Wallet Digitale Studente
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any
import json
import datetime
from pathlib import Path
from dataclasses import dataclass, asdict

# Directory Wallet 
WALLET_DIRECTORY = rf"C:\Users\maruo\Desktop\Group41_ProjectWork_APS"


@dataclass
class StudentInfo:
    """Informazioni studente"""
    student_id: str
    full_name: str
    email: str
    home_university: str = "salerno"  

@dataclass
class AcademicCredential:
    """Credenziale accademica"""
    credential_id: str
    issuer_university: str  
    issued_date: str
    student_info: StudentInfo
    academic_data: Dict[str, Any]  
    digital_signature: str  

class StudentWallet:
    """
    Wallet digitale studente:
    - Riceve credenziali da Rennes (università ospitante)
    - Invia credenziali a Salerno (università di origine)
    """
    
    def __init__(self, student_id: str, wallet_dir: str = None):
        """
        Inizializzazione Wallet Studente
        
        Args:
            student_id: ID univoco dello studente
            wallet_dir: Directory per salvare i file del wallet
        """
        self.student_id = student_id
        
        if wallet_dir is None:
            wallet_dir = WALLET_DIRECTORY
        
        self.wallet_dir = Path(wallet_dir)
        self.wallet_dir.mkdir(parents=True, exist_ok=True)
        
        self.received_credentials_dir = self.wallet_dir / "received_from_rennes"
        self.sent_credentials_dir = self.wallet_dir / "sent_to_salerno"
        
        self.received_credentials_dir.mkdir(exist_ok=True)
        self.sent_credentials_dir.mkdir(exist_ok=True)
        
        self.received_credentials = []
        self.sent_credentials = []
        
        print(f"Wallet studente inizializzato: {student_id}")
        print(f"Directory wallet: {self.wallet_dir}")

    def receive_credential_from_rennes(self, credential: AcademicCredential) -> str:
        """
        Riceve credenziale da Université de Rennes
        """

        print(f"\n RICEZIONE CREDENZIALE DA RENNES")
        print("=" * 40)
        
        if credential.issuer_university != "rennes":
            raise ValueError(f"Attesa credenziale da Rennes, ricevuta da: {credential.issuer_university}")
        
        credential_file = self.received_credentials_dir / f"{credential.credential_id}.json"
        
        with open(credential_file, 'w', encoding='utf-8') as f:
            json.dump(asdict(credential), f, indent=2, ensure_ascii=False)
        
        credential_ref = {
            "credential_id": credential.credential_id,
            "received_date": datetime.datetime.now().isoformat(),
            "file_path": str(credential_file),
            "issuer": credential.issuer_university,
            "student_name": credential.student_info.full_name
        }
        
        self.received_credentials.append(credential_ref)
         
        print(f"Credenziale ricevuta da Rennes con succeso.")
        print(f"  ID: {credential.credential_id}")
        print(f"  Studente: {credential.student_info.full_name}")
        print(f"  Esami: {len(credential.academic_data.get('exams', []))}")
        print(f"  File: {credential_file}")
        
        return credential.credential_id

    def send_credential_to_salerno(self, credential_id: str) -> bool:
        """
        Invio credenziale a Università di Salerno
        """
        print(f"\nINVIO CREDENZIALE A UNIVERSITÀ DI SALERNO")
        print("=" * 40)
        
        credential_ref = None
        for cred in self.received_credentials:
            if cred["credential_id"] == credential_id:
                credential_ref = cred
                break
        
        if not credential_ref:
            print(f"Errore: Credenziale non trovata: {credential_id}")
            return False
        
        source_file = Path(credential_ref["file_path"])
        if not source_file.exists():
            print(f"Errore: File credenziale non trovato: {source_file}")
            return False
        
        with open(source_file, 'r', encoding='utf-8') as f:
            credential_data = json.load(f)
        
        submission_package = {
            "submission_id": f"SUBMIT_{credential_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "submission_date": datetime.datetime.now().isoformat(),
            "student_id": self.student_id,
            "target_university": "salerno",
            "source_university": "rennes",
            "credential": credential_data,
            "submission_purpose": "credit_recognition",
            "student_request": f"Richiesta riconoscimento crediti Erasmus da {credential_data['issuer_university']}"
        }
        
        submission_file = self.sent_credentials_dir / f"submission_{credential_id}.json"
        
        with open(submission_file, 'w', encoding='utf-8') as f:
            json.dump(submission_package, f, indent=2, ensure_ascii=False)
        
        sent_ref = {
            "submission_id": submission_package["submission_id"],
            "credential_id": credential_id,
            "sent_date": submission_package["submission_date"],
            "target_university": "salerno",
            "file_path": str(submission_file),
            "status": "submitted"
        }
        
        self.sent_credentials.append(sent_ref)
        
        # Log operazione
        print(f"Credenziale inviata con succeso a Università di Salerno")
        
        return True

    def list_received_credentials(self):
        """Lista credenziali ricevute da Rennes"""
        print(f"\nCREDENZIALI RICEVUTE DA RENNES")
        print("=" * 50)
        
        if not self.received_credentials:
            print("Nessuna credenziale ricevuta ancora.")
            return
        
        for i, cred in enumerate(self.received_credentials, 1):
            print(f"{i}. {cred['credential_id']}")
            print(f"   Ricevuta: {cred['received_date']}")
            print(f"   Studente: {cred['student_name']}")
            print()

    def list_sent_credentials(self):
        """Lista credenziali inviate a Salerno"""
        print(f"\nCREDENZIALI INVIATE A SALERNO")
        print("=" * 50)
        
        if not self.sent_credentials:
            print("Nessuna credenziale inviata ancora.")
            return
        
        for i, sent in enumerate(self.sent_credentials, 1):
            print(f"{i}. {sent['submission_id']}")
            print(f"   Credenziale Originale: {sent['credential_id']}")
            print(f"   Inviata: {sent['sent_date']}")
            print(f"   Stato: {sent['status']}")
            print()

    def get_wallet_summary(self):
        """Mostra riassunto dello stato del wallet"""
        print(f"\nRIASSUNTO WALLET STUDENTE - {self.student_id}")
        print("=" * 50)
        print(f"Credenziali ricevute da Rennes: {len(self.received_credentials)}")
        print(f"Credenziali inviate a Salerno: {len(self.sent_credentials)}")
        print(f"Directory wallet: {self.wallet_dir}")
        
        # Calcola statistiche
        if self.received_credentials:
            print(f"\nStatistiche:")
            total_exams = 0
            for cred_ref in self.received_credentials:
                try:
                    with open(cred_ref["file_path"], 'r') as f:
                        cred_data = json.load(f)
                        total_exams += len(cred_data.get("academic_data", {}).get("exams", []))
                except:
                    pass
            print(f"   Esami totali da Erasmus: {total_exams}")

    def get_credential_details(self, credential_id: str) -> Optional[Dict]:
        """
        Ottieni dettagli completi di una credenziale
        """
        for cred_ref in self.received_credentials:
            if cred_ref["credential_id"] == credential_id:
                try:
                    with open(cred_ref["file_path"], 'r') as f:
                        return json.load(f)
                except Exception as e:
                    print(f"Errore caricamento credenziale {credential_id}: {e}")
                    return None
        return None

    def verify_credential_integrity(self, credential_id: str) -> bool:
        """
        Verifica integrità di una credenziale nel wallet
        """
        credential_data = self.get_credential_details(credential_id)
        if not credential_data:
            return False
        
        # Verifica campi obbligatori
        required_fields = ["credential_id", "issuer_university", "student_info", "academic_data", "digital_signature"]
        
        for field in required_fields:
            if field not in credential_data:
                print(f"Errore: Campo obbligatorio mancante: {field}")
                return False
        
        # Verifica che ci siano dati accademici
        academic_data = credential_data.get("academic_data", {})
        if not academic_data.get("exams"):
            print("Errore: Nessun dato accademico trovato")
            return False
        
        print(f"Integrità credenziale {credential_id} verificata")
        return True


def create_sample_rennes_credential(student_id: str) -> AcademicCredential:
    """
    Crea una credenziale esempio da Rennes
    (In un sistema reale, sarebbe creata e firmata dall'università)
    """
    student = StudentInfo(
        student_id=student_id,
        full_name="Alessandro Maruotto",
        email="a.maruotto@studenti.unisa.it",
        home_university="salerno"
    )
    
    credential = AcademicCredential(
        credential_id=f"RENNES_TRANSCRIPT_{student_id}_2024",
        issuer_university="rennes",
        issued_date=datetime.datetime.now().isoformat(),
        student_info=student,
        academic_data={
            "academic_year": "2024-2025",
            "semester": "2° semestre 2024",
            "erasmus_program": True,
            "exams": [
                {
                    "course_name": "Software Design Architecture",
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
                    "grade": "A-",
                    "exam_date": "2024-10-30"
                }
            ],
            "total_ects": 18,
        },
        digital_signature="rennes_digital_signature_placeholder"
    )
    
    return credential


def demo_wp1_scenario():
    """
    1. Studente riceve credenziali da Rennes
    2. Studente invia credenziali a Salerno per riconoscimento
    """
    print("SCENARIO WALLET STUDENTE ERASMUS")
    print("Studente riceve credenziali da Rennes, invia a Salerno")
    print()
    
    student_id = "0622702601"
    
    try:
        # 1. Inizializza wallet studente
        print("Fase 1: Inizializzazione wallet studente")
        wallet = StudentWallet(student_id)
        
        # 2. Simula ricezione credenziale da Rennes
        print("\nFase 2: Rennes emette credenziale per studente")
        rennes_credential = create_sample_rennes_credential(student_id)
        
        # 3. Studente riceve credenziale
        print("\nFase 3: Studente riceve credenziale da Rennes")
        received_id = wallet.receive_credential_from_rennes(rennes_credential)
        
        # 4. Mostra credenziali ricevute
        wallet.list_received_credentials()
        
        # 5. Verifica integrità
        print("\nFase 4: Verifica integrità credenziale")
        wallet.verify_credential_integrity(received_id)
        
        # 6. Studente invia credenziale a Salerno
        print("\nFase 5: Studente invia credenziale a Salerno")
        success = wallet.send_credential_to_salerno(received_id)
        
        if success:
            # 7. Mostra credenziali inviate
            wallet.list_sent_credentials()
            
            # 8. Riassunto finale
            wallet.get_wallet_summary()
            
            print(f"\nWALLET COMPLETATO CON SUCCESSO.")
            
            print(f"\nFile creati:")
            print(f"  Ricevute: {wallet.received_credentials_dir}")
            print(f"  Inviate: {wallet.sent_credentials_dir}")
        
    except Exception as e:
        print(f"Errore nello scenario wallet: {e}")
        import traceback
        traceback.print_exc()
