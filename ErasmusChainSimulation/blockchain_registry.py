#!/usr/bin/env python3
"""
Registro Blockchain per Credenziali Accademiche 
RESPONSABILITÀ: Solo gestione blockchain e smart contract
"""

import json
import datetime
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

class CredentialStatus(Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


@dataclass
class UniversityRegistration:
    """Registrazione università sulla blockchain"""
    university_id: str
    certificate_hash: str
    registration_date: str
    status: str = "active"


@dataclass
class CredentialRecord:
    """Record di credenziale sulla blockchain"""
    credential_id: str
    issuer_university: str
    merkle_root: str
    issue_date: str
    student_id_hash: str  # Hash dello student ID per privacy
    status: CredentialStatus
    revocation_reason: Optional[str] = None
    revocation_date: Optional[str] = None


@dataclass
class BlockchainTransaction:
    """Transazione blockchain simulata"""
    tx_id: str
    timestamp: str
    tx_type: str  # "register_university", "issue_credential", "revoke_credential"
    data: Dict[str, Any]
    block_number: int
    gas_used: int = 0


class AcademicCredentialSmartContract:
    """
    Simulazione Smart Contract Ethereum per credenziali accademiche
    Implementa le funzionalità descritte nel WP2
    """
    
    def __init__(self):
        """Inizializza lo smart contract"""
        self.registered_universities = {}  # university_id -> UniversityRegistration
        self.credential_records = {}  # credential_id -> CredentialRecord
        self.transaction_history = []  # Lista di transazioni
        self.block_number = 1
        
        print("Smart Contract Credenziali Accademiche inizializzato")
        print("Funzioni: register_university, issue_credential, revoke_credential, verify_status")
    
    def _generate_tx_id(self) -> str:
        """Genera ID transazione simulato"""
        timestamp = datetime.datetime.now().isoformat()
        return hashlib.sha256(f"{timestamp}{self.block_number}".encode()).hexdigest()[:16]
    
    def _hash_data(self, data: str) -> str:
        """Calcola hash SHA-256"""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def register_university(self, university_id: str, certificate_hash: str) -> str:
        """Registra un'università sulla blockchain (eseguita dalla CA)"""
        print(f"\nREGISTRAZIONE UNIVERSITÀ: {university_id}")
        print("=" * 40)
        
        if university_id in self.registered_universities:
            raise ValueError(f"Università {university_id} già registrata")
        
        # Crea registrazione
        registration = UniversityRegistration(
            university_id=university_id,
            certificate_hash=certificate_hash,
            registration_date=datetime.datetime.now().isoformat(),
            status="active"
        )
        
        # Salva registrazione
        self.registered_universities[university_id] = registration
        
        # Crea transazione
        tx_id = self._generate_tx_id()
        transaction = BlockchainTransaction(
            tx_id=tx_id,
            timestamp=datetime.datetime.now().isoformat(),
            tx_type="register_university",
            data=asdict(registration),
            block_number=self.block_number,
            gas_used=50000
        )
        
        self.transaction_history.append(transaction)
        self.block_number += 1
        
        print(f"Università registrata con successo")
        print(f"   TX ID: {tx_id}")
        print(f"   Hash Certificato: {certificate_hash}")
        print(f"   Blocco: {transaction.block_number}")
        
        return tx_id
    
    def issue_credential(self, 
                        credential_id: str, 
                        issuer_university: str,
                        merkle_root: str,
                        student_id: str) -> str:
        """Registra emissione di credenziale sulla blockchain"""
        print(f"\nEMISSIONE CREDENZIALE SU BLOCKCHAIN")
        print("=" * 40)
        
        # Verifica che l'università sia registrata
        if issuer_university not in self.registered_universities:
            raise ValueError(f"Università {issuer_university} non registrata")
            
        if self.registered_universities[issuer_university].status != "active":
            raise ValueError(f"Università {issuer_university} non attiva")
        
        # Verifica che la credenziale non esista già
        if credential_id in self.credential_records:
            raise ValueError(f"Credenziale {credential_id} già esistente")
        
        # Hash dello student ID per privacy
        student_id_hash = self._hash_data(student_id)
        
        # Crea record credenziale
        credential_record = CredentialRecord(
            credential_id=credential_id,
            issuer_university=issuer_university,
            merkle_root=merkle_root,
            issue_date=datetime.datetime.now().isoformat(),
            student_id_hash=student_id_hash,
            status=CredentialStatus.ACTIVE
        )
        
        # Salva record
        self.credential_records[credential_id] = credential_record
        
        # Crea transazione
        tx_id = self._generate_tx_id()
        transaction = BlockchainTransaction(
            tx_id=tx_id,
            timestamp=datetime.datetime.now().isoformat(),
            tx_type="issue_credential",
            data=asdict(credential_record),
            block_number=self.block_number,
            gas_used=75000
        )
        
        self.transaction_history.append(transaction)
        self.block_number += 1
        
        print(f"Credenziale registrata su blockchain")
        print(f"   ID Credenziale: {credential_id}")
        print(f"   Emittente: {issuer_university}")
        print(f"   Radice Merkle: {merkle_root}")
        print(f"   TX ID: {tx_id}")
        print(f"   Blocco: {transaction.block_number}")
        
        return tx_id
    
    def revoke_credential(self, 
                         credential_id: str, 
                         issuer_university: str,
                         reason: str) -> str:
        """Revoca una credenziale sulla blockchain"""
        print(f"\nREVOCA CREDENZIALE: {credential_id}")
        print("=" * 40)
        
        # Verifica che la credenziale esista
        if credential_id not in self.credential_records:
            raise ValueError(f"Credenziale {credential_id} non trovata")
        
        record = self.credential_records[credential_id]
        
        # Verifica che l'università sia autorizzata a revocare
        if record.issuer_university != issuer_university:
            raise ValueError(f"Solo l'emittente {record.issuer_university} può revocare questa credenziale")
        
        # Verifica che la credenziale sia attiva
        if record.status != CredentialStatus.ACTIVE:
            raise ValueError(f"Credenziale {credential_id} è già {record.status.value}")
        
        # Aggiorna status
        record.status = CredentialStatus.REVOKED
        record.revocation_reason = reason
        record.revocation_date = datetime.datetime.now().isoformat()
        
        # Crea transazione
        tx_id = self._generate_tx_id()
        transaction = BlockchainTransaction(
            tx_id=tx_id,
            timestamp=datetime.datetime.now().isoformat(),
            tx_type="revoke_credential",
            data={
                "credential_id": credential_id,
                "reason": reason,
                "revocation_date": record.revocation_date
            },
            block_number=self.block_number,
            gas_used=45000
        )
        
        self.transaction_history.append(transaction)
        self.block_number += 1
        
        print(f"Successo: Credenziale revocata con successo")
        print(f"   Motivo: {reason}")
        print(f"   TX ID: {tx_id}")
        print(f"   Blocco: {transaction.block_number}")
        
        return tx_id
    
    def verify_credential_status(self, credential_id: str) -> Dict[str, Any]:
        """Verifica lo status di una credenziale"""
        if credential_id not in self.credential_records:
            return {
                "exists": False,
                "credential_id": credential_id
            }
        
        record = self.credential_records[credential_id]
        
        return {
            "exists": True,
            "credential_id": credential_id,
            "issuer_university": record.issuer_university,
            "merkle_root": record.merkle_root,
            "issue_date": record.issue_date,
            "status": record.status.value,
            "revocation_reason": record.revocation_reason,
            "revocation_date": record.revocation_date
        }
    
    def get_university_credentials(self, university_id: str) -> List[Dict[str, Any]]:
        """Ottieni tutte le credenziali emesse da un'università"""
        credentials = []
        
        for credential_id, record in self.credential_records.items():
            if record.issuer_university == university_id:
                credentials.append({
                    "credential_id": credential_id,
                    "merkle_root": record.merkle_root,
                    "issue_date": record.issue_date,
                    "status": record.status.value,
                    "revocation_reason": record.revocation_reason,
                    "revocation_date": record.revocation_date
                })
        
        return credentials
    
    def get_blockchain_stats(self) -> Dict[str, Any]:
        """Statistiche della blockchain"""
        total_credentials = len(self.credential_records)
        active_credentials = sum(1 for r in self.credential_records.values() 
                               if r.status == CredentialStatus.ACTIVE)
        revoked_credentials = sum(1 for r in self.credential_records.values() 
                                if r.status == CredentialStatus.REVOKED)
        
        return {
            "total_universities": len(self.registered_universities),
            "total_credentials": total_credentials,
            "active_credentials": active_credentials,
            "revoked_credentials": revoked_credentials,
            "total_transactions": len(self.transaction_history),
            "current_block": self.block_number - 1
        }


class BlockchainIntegratedCredentialSystem:
    """
    Sistema di credenziali integrato con blockchain
    FOCUS: Solo operazioni blockchain
    """
    
    def __init__(self):
        """Inizializza il sistema integrato"""
        self.smart_contract = AcademicCredentialSmartContract()
        
        # Registra automaticamente le università
        self._register_universities()
    
    def _register_universities(self):
        """Registrazione Università di Salerno e di Rennes sulla blockchain"""
        print("CONFIGURAZIONE BLOCKCHAIN - REGISTRAZIONE UNIVERSITÀ")
        print("=" * 50)
        
        # Hash simulati dei certificati
        salerno_cert_hash = hashlib.sha256("UNISA-CERTIFICATE-X509".encode()).hexdigest()
        rennes_cert_hash = hashlib.sha256("RENNES-CERTIFICATE-X509".encode()).hexdigest()
        
        # Registra università
        self.smart_contract.register_university("salerno", salerno_cert_hash)
        self.smart_contract.register_university("rennes", rennes_cert_hash)
        
        print("Entrambe le università sono state registrate con successo sulla blockchain")
    
    def issue_and_register_credential(self, 
                                    credential_id: str,
                                    issuer_university: str,
                                    merkle_root: str,
                                    student_id: str) -> str:
        """Emette e registra credenziale sulla blockchain"""
        return self.smart_contract.issue_credential(
            credential_id, issuer_university, merkle_root, student_id
        )
    
    def verify_with_blockchain(self, credential_id: str, merkle_root: str) -> bool:
        """Verifica credenziale contro blockchain"""
        print(f"\nVERIFICA BLOCKCHAIN: {credential_id}")
        print("=" * 50)
        
        # Verifica status sulla blockchain
        status_info = self.smart_contract.verify_credential_status(credential_id)
        
        if not status_info["exists"]:
            print("Errore: Credenziale non trovata su blockchain")
            return False
        
        if status_info["status"] != "active":
            print(f"Errore: Stato credenziale: {status_info['status']}")
            if status_info["revocation_reason"]:
                print(f"   Motivo revoca: {status_info['revocation_reason']}")
            return False
        
        # Verifica Merkle root
        if status_info["merkle_root"] != merkle_root:
            print("Errore: Mismatch radice Merkle")
            print(f"   Attesa: {status_info['merkle_root']}")
            print(f"   Ricevuta: {merkle_root}")
            return False
        
        print("Credenziale verificata con successo sulla blockchain")
        print(f"   Emittente: {status_info['issuer_university']}")
        print(f"   Data Emissione: {status_info['issue_date']}")
        print(f"   Stato: {status_info['status']}")
        
        return True
    
    def revoke_credential(self, credential_id: str, issuer_university: str, reason: str) -> str:
        """Revoca credenziale"""
        return self.smart_contract.revoke_credential(credential_id, issuer_university, reason)
    
    def get_system_overview(self):
        """Mostra panoramica del sistema blockchain"""
        print("\nPANORAMICA SISTEMA CREDENZIALI BLOCKCHAIN")
        print("=" * 50)
        
        stats = self.smart_contract.get_blockchain_stats()
        
        print(f"Statistiche Sistema:")
        print(f"   Università registrate: {stats['total_universities']}")
        print(f"   Credenziali totali emesse: {stats['total_credentials']}")
        print(f"   Credenziali attive: {stats['active_credentials']}")
        print(f"   Credenziali revocate: {stats['revoked_credentials']}")
        print(f"   Transazioni blockchain: {stats['total_transactions']}")
        print(f"   Blocco corrente: {stats['current_block']}")
        
        # Mostra università registrate
        print(f"\nUniversità Registrate:")
        for uni_id, registration in self.smart_contract.registered_universities.items():
            print(f"   • {uni_id}: {registration.status} (dal {registration.registration_date[:10]})")


def demo_blockchain_integration():
    """Demo specifico per funzionalità blockchain"""
    print("DEMO INTEGRAZIONE BLOCKCHAIN")
    print("==============================")
    print("Scenario: Ciclo di vita completo credenziali con registro blockchain")
    print()
    
    try:
        # Inizializza sistema
        system = BlockchainIntegratedCredentialSystem()
        
        # Simula emissione credenziale
        print("\nFase 1: Emissione della credenziale e registrazione sulla blockchain")
        credential_id = "RENNES_CRED_0622702601_20250120"
        merkle_root = "abc123def456..."  # Simulato
        student_id = "0622702601"
        
        tx_id = system.issue_and_register_credential(
            credential_id, "rennes", merkle_root, student_id
        )
        
        # Verifica credenziale
        print("\nFase 2: Verifica credenziale contro blockchain")
        is_valid = system.verify_with_blockchain(credential_id, merkle_root)
        
        # Simula revoca
        print("\nFase 3: Revoca credenziale")
        revoke_tx = system.revoke_credential(
            credential_id, "rennes", "Discrepanza voti trovata"
        )
        
        # Verifica dopo revoca
        print("\nFase 4: Verifica credenziale revocata")
        is_valid_after_revoke = system.verify_with_blockchain(credential_id, merkle_root)
        
        # Panoramica finale
        system.get_system_overview()
        
        print(f"\nDEMO BLOCKCHAIN COMPLETATA")
        print("=" * 30)
        print(f"Credenziale emessa con successo: {tx_id}")
        print(f"Verifica iniziale: {'Valida' if is_valid else 'Non valida'}")
        print(f"Credenziale revocata: {revoke_tx}")
        print(f"Verifica post-revoca: {'Valida' if is_valid_after_revoke else 'Non valida'}")
        
    except Exception as e:
        print(f"Errore: Demo blockchain fallita: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    """Esecuzione diretta: solo demo blockchain integrazione"""
    print("MODULO BLOCKCHAIN WP2")
    print("======================")
    print()
    
    # Esegui direttamente la demo blockchain senza menu
    demo_blockchain_integration()
