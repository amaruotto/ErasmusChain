#!/usr/bin/env python3
"""
WP4 - Implementazione 

Fasi operative:
1. Configurazione PKI 
2. Richiesta Studente (Lo Studente richiede credenziali da Rennes)
3. Preparazione Merkle Tree (Rennes prepara struttura per la divulgazione selettiva)
4. Firma RSA-PSS (L'Università di Rennes firma digitalmente le credenziali)
5. Registrazione Blockchain (L'Università di Rennes registra su blockchain)
6. Consegna Credenziali (Lo studente riceve nel wallet)
7. Presentazione Selettiva (Lo studente crea presentazione privata)
8. Verifica Completa (L'Università di Salerno verifica lo stato di revoca e la validità degli esami)
"""

import os
import sys
import json
import time
import datetime
from pathlib import Path
from typing import Optional

# Directory certificati 
CA_DIRECTORY = rf"C:\Users\maruo\Desktop\Group41_ProjectWork_APS"

# Variabile globale per condividere smart contract tra fasi
global blockchain_contract_global
blockchain_contract_global = None

# Import cryptography per serialization
from cryptography.hazmat.primitives import serialization

# Path
current_dir = Path(__file__).parent.absolute()
sys.path.insert(0, str(current_dir))

def check_dependencies():
    """Verifica che tutte le dipendenze siano installate"""
    required_packages = [
        'cryptography'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"Errore: Pacchetti mancanti: {', '.join(missing)}")
        return False
    
    return True

def check_certificates(ca_dir: str = None) -> bool:
    """Verifica che i certificati siano stati generati"""
    if ca_dir is None:
        ca_dir = CA_DIRECTORY
    
    ca_path = Path(ca_dir)

    required_files = [
        "root/certs/root-ca.cert.pem",
        "salerno/certs/salerno-ca.cert.pem", 
        "salerno/private/salerno-ca.key.pem",
        "rennes/certs/rennes-ca.cert.pem",
        "rennes/private/rennes-ca.key.pem"
    ]
    
    missing_files = []
    for file_path in required_files:
        if not (ca_path / file_path).exists():
            missing_files.append(file_path)
    
    if missing_files:
        return False
    
    return True

def wait_for_user():
    """Pausa per permettere all'utente di seguire la storia"""
    print("\nPremere INVIO per procedere alla fase successiva")
    input()

def print_separator(title: str):
    print("\n" + "="*100)
    print(f"{title}")
    print("="*100)

def step_1_pki_setup():
    """Step 1: Setup infrastruttura PKI delle università"""
    print_separator("FASE 1: CONFIGURAZIONE INFRASTRUTTURA PKI UNIVERSITARIA")
    print()
    
    try:
        if not check_certificates():
            from certs import CertificateGenerator
            
            ca = CertificateGenerator(ca_dir=CA_DIRECTORY)
            
            root_key, root_cert = ca.create_root_ca()

            salerno_key, salerno_cert = ca.create_intermediate_ca_salerno(root_key, root_cert)
            
            rennes_key, rennes_cert = ca.create_intermediate_ca_rennes(root_key, root_cert)
            
            print("Infrastruttura PKI stabilita con successo.")
        else:
            print("Infrastruttura PKI già esistente")
            
        print("\nInfrastruttura Digitale Pronta:")
        print("  • Root CA Accademica: Autorità fidata per tutte le università")
        print("  • Università di Salerno (IT)")
        print("  • Université de Rennes (FR)")
            
    except Exception as e:
        print(f"Errore: Configurazione PKI fallita: {e}")
        return False
    
    return True

def step_2_student_request():
    """Step 2: Inizializzazione Wallet e richiesta di credenziali all'Università di Rennes"""
    print_separator("FASE 2: INIZIALIZZAZIONE WALLET E RICHIESTA DI CREDENZIALI ALL'UNIVERSITÀ DI RENNES")
    print()
    
    try:
        # Inizializzazione Wallet
        from wallet import StudentWallet, StudentInfo
        
        print("Fase 2.1: Inizializzazione Wallet Digitale di Alessandro")
        
        # Info studente
        alessandro_info = StudentInfo(
            student_id="0622702601",
            full_name="Alessandro Maruotto",
            email="a.maruotto1@studenti.unisa.it",
            home_university="salerno"
        )
        
        # Inizializzazione Wallet
        alessandro_wallet = StudentWallet("0622702601")
        
        print(f"Wallet digitale inizializzato con successo.")
        print(f"   Proprietario: {alessandro_info.full_name}")
        print(f"   ID Studente: {alessandro_info.student_id}")
        print(f"   Università di Origine: {alessandro_info.home_university}")
        
        # Richiesta di credenziali all'Universitò di Rennes
        print(f"\nFase 2.2: Invio Richiesta Ufficiale Credenziali all'Università di Rennes")
        
        credential_request = {
            "request_id": f"REQ_RENNES_{alessandro_info.student_id}_{datetime.datetime.now().strftime('%Y%m%d')}",
            "request_date": datetime.datetime.now().isoformat(),
            "student_info": {
                "id": alessandro_info.student_id,
                "name": alessandro_info.full_name,
                "email": alessandro_info.email,
                "home_university": alessandro_info.home_university
            },
            "wallet_ready": True,
            "erasmus_period": {
                "start_date": "2024-09-15",
                "end_date": "2024-12-20",
                "academic_year": "2024-2025",
                "semester": "2° semestre 2024"
            },
            "requested_credentials": {
                "type": "official_transcript",
                "purpose": "credit_recognition",
                "target_university": "Università di Salerno",
                "include_grades": True,
                "include_ects": True,
                "format": "digital_verifiable"
            },
            "courses_completed": [
                {"code": "INFO5001", "name": "Software Design Architecture", "status": "completed"},
                {"code": "INFO5002", "name": "Machine Learning", "status": "completed"},
                {"code": "INFO5003", "name": "Embedded System", "status": "completed"}
            ]
        }
        
        print(f"Dettagli Richiesta:")
        print(f"   ID Richiesta: {credential_request['request_id']}")
        print(f"   Studente: {alessandro_info.full_name} ({alessandro_info.student_id})")
        print(f"   Periodo: {credential_request['erasmus_period']['semester']}")
        print(f"   Corsi: {len(credential_request['courses_completed'])} completati")
        
        print(f"\nRichiesta inviata con successo all'Ufficio Registrazione di Rennes.")
        
        global alessandro_request_data, alessandro_wallet_global
        alessandro_request_data = credential_request
        alessandro_wallet_global = alessandro_wallet
        
        return True
        
    except Exception as e:
        print(f"Errore: Preparazione studente fallita: {e}")
        return False

def step_3_merkle_preparation():
    """Step 3: Università di Rennes riceve la richiesta e prepara il Merkle Tree per divulgazione selettiva"""
    print_separator("FASE 3: RENNES PREPARA LE CREDENZIALI DI INVIARE AL WALLET DELLO STUDENTE")
    
    print("Creazione struttura Merkle Tree per divulgazione selettiva...")
    print()
    
    try:
        from merkle_credentials import MerkleCredentialTree
        
        # Dati accademici di Alessandro da Rennes
        alessandro_academic_data = {
            "academic_year": "2024-2025",
            "semester": "2° semestre 2024",
            "erasmus_program": True,
            "student_id": "0622702601",
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
                    "grade": "C",      
                    "exam_date": "2024-10-30"
                }
            ],
            "total_ects": 18,
        }
        
        # Costruzione Merkle Tree
        print(f"\nCostruzione Merkle Tree per divulgazione selettiva.")
        tree = MerkleCredentialTree()
        merkle_root = tree.build_tree(alessandro_academic_data)
        
        tree_info = tree.get_tree_info()
        print(f"Merkle Tree costruito con successo.")
        print(f"   • Hash radice: {merkle_root[:32]}...")
        print(f"   • Livelli albero: {tree_info['num_levels']}")
        print(f"   • Campi dati: {tree_info['num_leaves']}")
        
        global alessandro_merkle_tree, alessandro_academic_data_global
        alessandro_merkle_tree = tree
        alessandro_academic_data_global = alessandro_academic_data
        
        return True
        
    except Exception as e:
        print(f"Errore: Preparazione Merkle Tree fallita: {e}")
        return False

def step_4_rsa_pss_signing():
    """Step 4: Firma digitale delle credenziali da parte dell'Università di Rennes"""
    print_separator("FASE 4: FIRMA DIGITALE DELLE CREDENZIALI DALL'UNIVERSITÀ DI RENNES")
    print()
    
    try:
        from certs import CertificateGenerator
        import json
        
        ca = CertificateGenerator(ca_dir=CA_DIRECTORY)
        rennes_key, rennes_cert = ca.load_university_key("rennes")
        
        credential_package = {
            "credential_id": f"RENNES_OFFICIAL_{alessandro_request_data['student_info']['id']}_{datetime.datetime.now().strftime('%Y%m%d')}",
            "issued_by": "Université de Rennes",
            "issued_to": alessandro_request_data['student_info'],
            "issue_date": datetime.datetime.now().isoformat(),
            "academic_data": alessandro_academic_data_global,
            "merkle_root": alessandro_merkle_tree.merkle_root,
            "erasmus_period": alessandro_request_data['erasmus_period'],
            "credential_type": "official_academic_transcript"
        }
        
        data_to_sign = json.dumps(credential_package, sort_keys=True, ensure_ascii=False)
        
        print(f"Credenziali:")
        print(f"   ID Credenziale: {credential_package['credential_id']}")
        print(f"   Data emissione: {credential_package['issue_date'][:10]}")
        print(f"   Radice Merkle: {credential_package['merkle_root'][:32]}...")
        print(f"   Dimensione dati: {len(data_to_sign)} caratteri")
        
        signature = ca.sign_data_rsa_pss(rennes_key, data_to_sign)
        is_valid = ca.verify_signature_rsa_pss(rennes_cert.public_key(), data_to_sign, signature)
        
        if is_valid:
            print(f"Firma Digitale applicata con successo.")

            global alessandro_signed_credential
            alessandro_signed_credential = {
                "credential_data": credential_package,
                "digital_signature": signature,
                "signer_certificate": rennes_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            }
            
            return True
        else:
            print(f"Errore: Verifica firma fallita.")
            return False
            
    except Exception as e:
        print(f"Errore: Firma RSA-PSS fallita: {e}")
        return False

def step_5_blockchain_registration():
    """Step 5: Registrazione delle credenziali da parte dell'Università di Rennes"""
    print_separator("FASE 5: REGISTRAZIONE DELLE CREDENZIALI SULLA BLOCKCHAIN DA PARTE DELL'UNIVERSITÀ DI RENNES")
    print()
    
    try:
        from blockchain_registry import AcademicCredentialSmartContract
        
        # Inizializzazione Smart Contract
        print("Inizializzazione Smart Contract Credenziali Accademiche")
        global blockchain_contract_global
        if blockchain_contract_global is None:
            blockchain_contract_global = AcademicCredentialSmartContract()
        contract = blockchain_contract_global
        
        # Registrazione dell'Università di Rennes
        try:
            import hashlib
            rennes_cert_hash = hashlib.sha256("RENNES-UNIVERSITY-CERT".encode()).hexdigest()
            tx1 = contract.register_university("rennes", rennes_cert_hash)
            print(f"   • Registrazione università: {tx1[:16]}...")
        except:
            print(f"   • Rennes già registrata")
        
        # Registrazione Credenziale
        credential_id = alessandro_signed_credential['credential_data']['credential_id']
        merkle_root = alessandro_signed_credential['credential_data']['merkle_root']
        student_id = alessandro_signed_credential['credential_data']['issued_to']['id']
        
        tx2 = contract.issue_credential(
            credential_id=credential_id,
            issuer_university="rennes",
            merkle_root=merkle_root,
            student_id=student_id
        )
        
        print(f"Credenziale registrata con successo sulla Blockchain.")
        print(f"   ID Transazione: {tx2}")
        print(f"   ID Credenziale: {credential_id}")
        print(f"   Radice Merkle: {merkle_root[:32]}...")
        print(f"   ID Studente (hash): Protetto per privacy")
        
        status = contract.verify_credential_status(credential_id)
        
        if status['exists'] and status['status'] == 'active':
            print(f"Verifica blockchain riuscita.")
            print(f"   Stato: {status['status']}")
            print(f"   Emittente: {status['issuer_university']}")
            print(f"   Data emissione: {status['issue_date'][:10]}")
            
            global alessandro_blockchain_status
            alessandro_blockchain_status = status
            
            return True
        else:
            print(f"Errore: Verifica blockchain fallita.")
            return False
            
    except Exception as e:
        print(f"Errore: Registrazione blockchain fallita: {e}")
        return False

def step_6_credential_delivery():
    """Step 6: Ricezione delle credenziali nel Wallet"""
    print_separator("FASE 6: EMISSIONE DELLE CREDENZIALI SUL WALLET DELLO STUDENTE")
    
    try:
        from wallet import AcademicCredential, StudentInfo
        
        global alessandro_wallet_global
        if alessandro_wallet_global is None:
            print("Errore: Wallet non trovato:")
            return False
        
        print(f"Utilizzo Wallet esistente: {alessandro_wallet_global.wallet_dir}")
        
        alessandro_student_info = StudentInfo(
            student_id="0622702601",
            full_name="Alessandro Maruotto",
            email="a.maruotto@studenti.unisa.it",
            home_university="salerno"
        )
        
        credential_for_wallet = AcademicCredential(
            credential_id=alessandro_signed_credential['credential_data']['credential_id'],
            issuer_university="rennes",
            issued_date=alessandro_signed_credential['credential_data']['issue_date'],
            student_info=alessandro_student_info,
            academic_data=alessandro_signed_credential['credential_data']['academic_data'],
            digital_signature=alessandro_signed_credential['digital_signature']
        )
        
        print(f"Pacchetto credenziali pronto per l'emissione:")
        print(f"   Da: Université de Rennes")
        print(f"   A: {alessandro_student_info.full_name}")
        
        print(f"\nEmissione della credenziale sull wallet dello Studente")
        received_id = alessandro_wallet_global.receive_credential_from_rennes(credential_for_wallet)
        integrity_ok = alessandro_wallet_global.verify_credential_integrity(received_id)
        
        if integrity_ok:
            print(f"Credenziale ricevuta e verificata con successo.")
            alessandro_wallet_global.get_wallet_summary()

            return True
        else:
            print(f"Errore: Verifica integrità credenziale fallita!")
            return False
            
    except Exception as e:
        print(f"Errore: Consegna credenziale fallita: {e}")
        return False

def step_7_selective_presentation():
    """Step 7: Generazione della presentazione selettiva"""
    print_separator("FASE 7: GENERAZIONE DELLA PRESENTAZIONE SELETTIVA")

    try:
        from merkle_credentials import MerkleProof
        
        print("Lo studente:")
        print("   RIVELA: Software Design Architecture (Voto: A)")
        print("   RIVELA: Machine Learning (Voto: B+)")
        print("   NASCONDE: Embedded Systems (Voto: C)")
        
        # Campi che lo studente vuole rivelare
        fields_to_disclose = [
            'academic_year',
            'semester', 
            'total_ects',
            'exam_0',  # Software Architecture Design (A)
            'exam_1',  # Machine Learning (B+)
            # exam_2 (Embedded Systems - C) rimane nascosto
        ]
        
        available_fields = []

        base_fields = ['academic_year', 'semester', 'total_ects']
        for field in base_fields:
            if field in alessandro_academic_data_global:
                available_fields.append(field)
        
        if 'exams' in alessandro_academic_data_global:
            for i in range(len(alessandro_academic_data_global['exams'])):
                available_fields.append(f'exam_{i}')
        
        valid_fields = [field for field in fields_to_disclose if field in available_fields]
        invalid_fields = [field for field in fields_to_disclose if field not in available_fields]
        
        if invalid_fields:
            print(f"Avviso: Rimozione campi non validi: {invalid_fields}")
            print(f"Campi disponibili: {available_fields}")
            fields_to_disclose = valid_fields
        
        print(f"Utilizzo campi validi: {fields_to_disclose}")
        
        # Genera prove Merkle per campi selezionati
        selective_proofs = []
        for field_name in fields_to_disclose:
            proof = alessandro_merkle_tree.generate_proof(field_name, alessandro_academic_data_global)
            if proof:
                proof_data = {
                    'field_name': proof.field_name,
                    'field_value': proof.field_value,
                    'field_hash': proof.field_hash,
                    'proof_path': proof.proof_path,
                    'proof_directions': proof.proof_directions,
                    'merkle_root': proof.merkle_root
                }
                selective_proofs.append(proof_data)
                
                if field_name.startswith('exam_'):
                    exam_data = proof.field_value
                    print(f"   Verificato: {exam_data['course_name']}: Voto {exam_data['grade']} ({exam_data['ects_credits']} ECTS)")
                else:
                    print(f"   Verificato: {field_name}: {proof.field_value}")
        
        print(f"\nInformazioni nascoste:")
        hidden_exam = alessandro_academic_data_global['exams'][2]  # Database Systems
        print(f"   Nascosto: {hidden_exam['course_name']}: Voto {hidden_exam['grade']} (6 ECTS)")
        
        # Crea pacchetto presentazione
        presentation_package = {
            "presentation_id": f"PRES_SALERNO_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "original_credential_id": alessandro_signed_credential['credential_data']['credential_id'],
            "presented_fields": fields_to_disclose,
            "merkle_proofs": selective_proofs,
            "merkle_root": alessandro_merkle_tree.merkle_root,
            "presentation_date": datetime.datetime.now().isoformat(),
            "target_university": "salerno",
            "privacy_note": "Voto per Database Systems (INFO5003) nascosto per scelta dello studente"
        }
        
        print(f"\nPresentazione selettiva creata:")
        print(f"   ID Presentazione: {presentation_package['presentation_id']}")
        print(f"   Campi rivelati: {len(selective_proofs)}")
        print(f"   Campi nascosti: 1 (voto Database Systems)")
        
        global alessandro_presentation
        alessandro_presentation = presentation_package
        
        return True
        
    except Exception as e:
        print(f"Errore: Presentazione selettiva fallita: {e}")
        return False

def step_8_complete_verification():
    """Step 8: Verifica credenziali da parte dell'Università di Salerno (firma + Merkle + blockchain)"""
    print_separator("FASE 8: VERIFICA CREDENZIALI DA PARTE DELL'UNIVERSITÀ DI SALERNO")
    
    try:
        from certs import CertificateGenerator
        from blockchain_registry import AcademicCredentialSmartContract
        from cryptography import x509
        import json
        
        verification_results = {}
        
        # 1. Verifica Blockchain
        print("Fase 8.1: Verifica Stato Blockchain")
        
        global blockchain_contract_global
        if blockchain_contract_global is not None:
            contract = blockchain_contract_global
        else:
            contract = AcademicCredentialSmartContract()
        
        credential_id = alessandro_presentation['original_credential_id']
        
        blockchain_status = contract.verify_credential_status(credential_id)
        if blockchain_status['exists'] and blockchain_status['status'] == 'active':
            print(f"Credenziale correttamente caricata.")
            print(f"   Emittente confermato: {blockchain_status['issuer_university']}")
            print(f"   Data emissione: {blockchain_status['issue_date'][:10]}")
            print(f"   Stato: {blockchain_status['status']}")
            verification_results['blockchain'] = True
        else:
            print(f"   Errore Blockchain: Credenziale non trovata o revocata")
            verification_results['blockchain'] = False
        
        # 2. Verifica Firma Digitale RSA-PSS
        print(f"\nFase 8.2: Verifica Firma Digitale RSA-PSS")
        ca = CertificateGenerator(ca_dir=CA_DIRECTORY)
        
        # Ricostruzione dati originali
        original_data = json.dumps(alessandro_signed_credential['credential_data'], sort_keys=True, ensure_ascii=False)
        signature = alessandro_signed_credential['digital_signature']
        
        # Caricamento certificato Rennes
        rennes_cert_pem = alessandro_signed_credential['signer_certificate']
        rennes_cert = x509.load_pem_x509_certificate(rennes_cert_pem.encode('utf-8'))
        
        # Verifica firma
        signature_valid = ca.verify_signature_rsa_pss(rennes_cert.public_key(), original_data, signature)
        
        if signature_valid:
            print(f"   Firma Digitale verificata con successo")
            verification_results['signature'] = True
        else:
            print(f"   Errore Firma Digitale: Non valida o manomessa")
            verification_results['signature'] = False
        
        # 3. Verifica Merkle Proofs (Selective Disclosure)
        print(f"\nFase 8.3: Verifica Prove Merkle Tree")
        
        from merkle_credentials import MerkleCredentialTree, MerkleProof
        
        verification_tree = MerkleCredentialTree()
        verification_tree.merkle_root = alessandro_presentation['merkle_root']
        
        valid_proofs = 0
        total_proofs = len(alessandro_presentation['merkle_proofs'])
        disclosed_data = {}
        
        for proof_data in alessandro_presentation['merkle_proofs']:
            proof = MerkleProof(
                field_name=proof_data['field_name'],
                field_value=proof_data['field_value'],
                field_hash=proof_data['field_hash'],
                proof_path=proof_data['proof_path'],
                proof_directions=proof_data['proof_directions'],
                merkle_root=proof_data['merkle_root']
            )
            
            is_valid = verification_tree.verify_proof(proof)
            if is_valid:
                valid_proofs += 1
                disclosed_data[proof.field_name] = proof.field_value
        
        if valid_proofs == total_proofs:
            print(f"   Prove Merkle verificata con successo")
            verification_results['merkle_proofs'] = True
        else:
            print(f"   Errore Prove Merkle: {valid_proofs}/{total_proofs} valide")
            verification_results['merkle_proofs'] = False
        
        # 4. Analisi Crediti Riconoscibili
        print(f"\nFase 8.4: Analisi Crediti Accademici")
        
        total_disclosed_ects = 0
        recognized_courses = []
        
        for field_name, field_value in disclosed_data.items():
            if field_name.startswith('exam_'):
                exam = field_value
                total_disclosed_ects += exam['ects_credits']
                recognized_courses.append({
                    'course': exam['course_name'],
                    'grade': exam['grade'],
                    'ects': exam['ects_credits']
                })
        
        print(f"   Risultati accademici rivelati:")
        for course in recognized_courses:
            print(f"     • {course['course']}: Voto {course['grade']} ({course['ects']} ECTS)")
        
        # 5. Decisione Finale
        print(f"\nFase 8.5: Decisione Finale di Salerno")
        
        all_verifications_passed = all(verification_results.values())
        
        if all_verifications_passed:
            print(f"   VERIFICA - CREDITI APPROVATI")
            print(f"   Decisione riconoscimento:")
            print(f"     • Stato: APPROVATO per riconoscimento crediti")
            print(f"     • ECTS riconosciuti: {total_disclosed_ects}")

            print_separator(f"TRASFERIMENTO DELLE CREDENZIALI COMPLETATO.")
            
        else:
            print(f"   Errore VERIFICA FALLITA - CREDITI NEGATI")
            failed_checks = [check for check, result in verification_results.items() if not result]
            print(f"   Verifiche fallite: {', '.join(failed_checks)}")
        
        return all_verifications_passed
        
    except Exception as e:
        print(f"Errore: Verifica completa fallita: {e}")
        return False

def run_realistic_erasmus_flow():
    
    # Inizializza variabili globali per condividere dati tra step
    global alessandro_request_data, alessandro_merkle_tree, alessandro_academic_data_global
    global alessandro_signed_credential, alessandro_blockchain_status, alessandro_wallet_global, alessandro_presentation
    
    results = {}
    
    # Step 1: PKI Setup
    results['pki_setup'] = step_1_pki_setup()
    wait_for_user()
    
    # Step 2: Student Request
    results['student_request'] = step_2_student_request()
    wait_for_user()
    
    # Step 3: Merkle Preparation
    results['merkle_preparation'] = step_3_merkle_preparation()
    wait_for_user()
    
    # Step 4: RSA-PSS Signing
    results['rsa_pss_signing'] = step_4_rsa_pss_signing()
    wait_for_user()
    
    # Step 5: Blockchain Registration
    results['blockchain_registration'] = step_5_blockchain_registration()
    wait_for_user()
    
    # Step 6: Credential Delivery
    results['credential_delivery'] = step_6_credential_delivery()
    wait_for_user()
    
    # Step 7: Selective Presentation
    results['selective_presentation'] = step_7_selective_presentation()
    wait_for_user()
    
    # Step 8: Complete Verification
    results['complete_verification'] = step_8_complete_verification()

def main():
    print("="*80)
    print("SISTEMA DI INVIO DI CREDENZIALI ACCADEMICHE")
    print("="*80)
    
    print("\nPremere INVIO per continuare")
    input()
    
    run_realistic_erasmus_flow()

if __name__ == "__main__":
    main()