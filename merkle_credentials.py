#!/usr/bin/env python3
"""
Merkle Tree implementation for selective disclosure of academic credentials
Based on WP2 specifications
"""

import hashlib
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import math


@dataclass
class MerkleProof:
    """Prova Merkle per un campo specifico"""
    field_name: str
    field_value: Any
    field_hash: str
    proof_path: List[str]  # Lista di hash siblings nel percorso verso la root
    proof_directions: List[str]  # Lista di 'left' o 'right' per ogni hash nel path
    merkle_root: str


class MerkleCredentialTree:
    """
    Implementazione Merkle Tree per credenziali accademiche
    Permette divulgazione selettiva come specificato nel WP2
    """
    
    def __init__(self):
        self.tree_levels = []  # Lista di livelli dell'albero
        self.field_positions = {}  # Mapping campo -> posizione nelle foglie
        self.merkle_root = None
        
    def hash_data(self, data: str) -> str:
        """Calcola SHA-256 hash di un dato"""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def prepare_credential_fields(self, academic_data: Dict[str, Any]) -> List[Tuple[str, str]]:
        """
        Prepara i campi della credenziale per il Merkle Tree
        
        Args:
            academic_data: Dati accademici dalla credenziale
            
        Returns:
            Lista di tuple (field_name, field_hash)
        """
        fields = []
        
        # Campi base
        if 'academic_year' in academic_data:
            field_value = str(academic_data['academic_year'])
            field_hash = self.hash_data(f"academic_year:{field_value}")
            fields.append(('academic_year', field_hash))
            
        if 'semester' in academic_data:
            field_value = str(academic_data['semester'])
            field_hash = self.hash_data(f"semester:{field_value}")
            fields.append(('semester', field_hash))
            
        if 'total_ects' in academic_data:
            field_value = str(academic_data['total_ects'])
            field_hash = self.hash_data(f"total_ects:{field_value}")
            fields.append(('total_ects', field_hash))
            
        # Esami individuali
        if 'exams' in academic_data:
            for i, exam in enumerate(academic_data['exams']):
                # Ogni esame diventa un campo separato
                exam_json = json.dumps(exam, sort_keys=True)
                field_name = f"exam_{i}"
                field_hash = self.hash_data(f"{field_name}:{exam_json}")
                fields.append((field_name, field_hash))
                
        # Coordinatore
        if 'coordinator' in academic_data:
            field_value = str(academic_data['coordinator'])
            field_hash = self.hash_data(f"coordinator:{field_value}")
            fields.append(('coordinator', field_hash))
            
        return fields
    
    def build_tree(self, academic_data: Dict[str, Any]) -> str:
        """
        Costruisce il Merkle Tree dai dati accademici
        
        Args:
            academic_data: Dati accademici dalla credenziale
            
        Returns:
            Merkle root hash
        """
        print(f"\nCOSTRUZIONE MERKLE TREE")
        print("=" * 30)
        
        # Prepara i campi
        fields = self.prepare_credential_fields(academic_data)
        print(f"Preparati {len(fields)} campi per l'albero")
        
        # Crea le foglie (livello 0)
        leaves = []
        for i, (field_name, field_hash) in enumerate(fields):
            leaves.append(field_hash)
            self.field_positions[field_name] = i
            print(f"  {i}: {field_name} -> {field_hash[:16]}...")
            
        # Assicurati che il numero di foglie sia una potenza di 2
        original_count = len(leaves)
        while len(leaves) & (len(leaves) - 1) != 0:
            # Aggiungi hash di padding
            padding_hash = self.hash_data("PADDING")
            leaves.append(padding_hash)
            
        print(f"Espanso da {original_count} a {len(leaves)} foglie")
        
        # Inizializza i livelli dell'albero
        self.tree_levels = [leaves]
        current_level = leaves
        
        # Costruisci l'albero dal basso verso l'alto
        level_num = 0
        while len(current_level) > 1:
            next_level = []
            
            # Combina coppie di nodi
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
                
                # Parent = H(left || right)
                parent_hash = self.hash_data(f"{left}{right}")
                next_level.append(parent_hash)
                
            self.tree_levels.append(next_level)
            current_level = next_level
            level_num += 1
            print(f"  Livello {level_num}: {len(current_level)} nodi")
            
        # Root è l'unico nodo rimasto
        self.merkle_root = current_level[0]
        print(f"Radice Merkle: {self.merkle_root}")
        
        return self.merkle_root
    
    def generate_proof(self, field_name: str, academic_data: Dict[str, Any]) -> Optional[MerkleProof]:
        """
        Genera prova Merkle per un campo specifico
        
        Args:
            field_name: Nome del campo per cui generare la prova
            academic_data: Dati accademici originali
            
        Returns:
            MerkleProof se il campo esiste, None altrimenti
        """
        if field_name not in self.field_positions:
            print(f"Campo '{field_name}' non trovato nell'albero")
            return None
            
        position = self.field_positions[field_name]
        print(f"\nGENERAZIONE PROVA PER: {field_name} (posizione {position})")
        
        # Ottieni il valore del campo
        field_value = self._get_field_value(field_name, academic_data)
        if field_value is None:
            return None
            
        # Calcola l'hash del campo
        if field_name.startswith('exam_'):
            exam_index = int(field_name.split('_')[1])
            field_value_json = json.dumps(academic_data['exams'][exam_index], sort_keys=True)
            field_hash = self.hash_data(f"{field_name}:{field_value_json}")
        else:
            field_hash = self.hash_data(f"{field_name}:{str(field_value)}")
        
        # Genera il percorso di prova
        proof_path = []
        proof_directions = []
        current_position = position
        
        # Attraversa l'albero dal basso verso l'alto
        for level in range(len(self.tree_levels) - 1):
            current_level = self.tree_levels[level]
            
            # Trova il sibling
            if current_position % 2 == 0:
                # Nodo sinistro, sibling è a destra
                if current_position + 1 < len(current_level):
                    sibling_hash = current_level[current_position + 1]
                    proof_path.append(sibling_hash)
                    proof_directions.append('right')
                else:
                    # Non c'è sibling destro, usa se stesso
                    sibling_hash = current_level[current_position]
                    proof_path.append(sibling_hash)
                    proof_directions.append('right')
            else:
                # Nodo destro, sibling è a sinistra
                sibling_hash = current_level[current_position - 1]
                proof_path.append(sibling_hash)
                proof_directions.append('left')
                
            # Muovi al livello superiore
            current_position = current_position // 2
            
        print(f"Lunghezza percorso prova: {len(proof_path)}")
        
        return MerkleProof(
            field_name=field_name,
            field_value=field_value,
            field_hash=field_hash,
            proof_path=proof_path,
            proof_directions=proof_directions,
            merkle_root=self.merkle_root
        )
    
    def verify_proof(self, proof: MerkleProof) -> bool:
        """
        Verifica una prova Merkle
        
        Args:
            proof: Prova Merkle da verificare
            
        Returns:
            True se la prova è valida, False altrimenti
        """
        print(f"\nVERIFICA PROVA PER: {proof.field_name}")
        
        # Inizia con l'hash del campo
        current_hash = proof.field_hash
        
        # Attraversa il percorso di prova
        for i, (sibling_hash, direction) in enumerate(zip(proof.proof_path, proof.proof_directions)):
            if direction == 'right':
                # Il sibling è a destra
                current_hash = self.hash_data(f"{current_hash}{sibling_hash}")
            else:
                # Il sibling è a sinistra
                current_hash = self.hash_data(f"{sibling_hash}{current_hash}")
                
            print(f"  Passo {i+1}: sibling {direction} -> {current_hash[:16]}...")
        
        # Verifica che il risultato finale sia uguale alla root
        is_valid = current_hash == proof.merkle_root
        print(f"Hash finale: {current_hash}")
        print(f"Radice attesa: {proof.merkle_root}")
        print(f"Prova valida: {is_valid}")
        
        return is_valid
    
    def _get_field_value(self, field_name: str, academic_data: Dict[str, Any]) -> Any:
        """Ottieni il valore di un campo dai dati accademici"""
        if field_name == 'academic_year':
            return academic_data.get('academic_year')
        elif field_name == 'semester':
            return academic_data.get('semester')
        elif field_name == 'total_ects':
            return academic_data.get('total_ects')
        elif field_name == 'coordinator':
            return academic_data.get('coordinator')
        elif field_name.startswith('exam_'):
            exam_index = int(field_name.split('_')[1])
            exams = academic_data.get('exams', [])
            if exam_index < len(exams):
                return exams[exam_index]
        return None
    
    def get_tree_info(self) -> Dict[str, Any]:
        """Restituisce informazioni sull'albero"""
        return {
            'merkle_root': self.merkle_root,
            'num_levels': len(self.tree_levels),
            'num_leaves': len(self.tree_levels[0]) if self.tree_levels else 0,
            'fields': list(self.field_positions.keys())
        }


def demo_selective_disclosure():
    """
    Demo della divulgazione selettiva con Merkle Trees
    Simula il caso d'uso WP2
    """
    print("DEMO DIVULGAZIONE SELETTIVA")
    print("============================")
    print("Scenario: Lo studente presenta solo campi selezionati a Salerno")
    print()
    
    # Dati accademici completi da Rennes
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
                "grade": "C",  # Voto basso che lo studente vuole nascondere
                "exam_date": "2024-10-30"
            }
        ],
        "total_ects": 18,
    }
    
    try:
        # 1. Rennes costruisce il Merkle Tree (durante l'emissione)
        print("Passo 1: Rennes costruisce il Merkle Tree per la credenziale")
        tree = MerkleCredentialTree()
        merkle_root = tree.build_tree(academic_data)
        
        print(f"\nInformazioni albero:")
        info = tree.get_tree_info()
        for key, value in info.items():
            print(f"  {key}: {value}")
        
        # 2. Studente decide quali campi rivelare (nasconde l'esame con voto C)
        print(f"\nPasso 2: Lo studente seleziona i campi da divulgare")
        fields_to_disclose = [
            'academic_year',
            'semester', 
            'total_ects',
            'exam_0',  # Software Design Architecture (A)
            'exam_1',  # Machine Learning (B+)
            # Nasconde exam_2 (Embedded Systems con voto C)
            'coordinator'
        ]
        
        print(f"Lo studente divulgherà: {fields_to_disclose}")
        print(f"Lo studente nasconderà: exam_2 (Database Systems - Voto C)")
        
        # 3. Genera prove per i campi selezionati
        print(f"\nPasso 3: Generazione prove per i campi selezionati")
        proofs = []
        for field_name in fields_to_disclose:
            proof = tree.generate_proof(field_name, academic_data)
            if proof:
                proofs.append(proof)
        
        print(f"Generate {len(proofs)} prove")
        
        # 4. Salerno verifica le prove (senza accesso ai dati nascosti)
        print(f"\nPasso 4: Salerno verifica i campi divulgati")
        all_valid = True
        
        for proof in proofs:
            is_valid = tree.verify_proof(proof)
            if not is_valid:
                all_valid = False
                print(f"Prova non valida per {proof.field_name}")
            else:
                print(f"Prova valida per {proof.field_name}: {proof.field_value}")
        
        # 5. Risultato finale
        print(f"\nDIVULGAZIONE SELETTIVA COMPLETATA")
        print(f"=" * 40)
        
        if all_valid:
            print(f"Tutti i campi divulgati sono stati verificati con successo.")
            print(f"Salerno può vedere:")
            for proof in proofs:
                if proof.field_name.startswith('exam_'):
                    exam_data = proof.field_value
                    print(f"  • {exam_data['course_name']}: {exam_data['grade']} ({exam_data['ects_credits']} ECTS)")
                else:
                    print(f"  • {proof.field_name}: {proof.field_value}")
            
            print(f"\nNascosto a Salerno:")
            hidden_exam = academic_data['exams'][2]
            print(f"  • {hidden_exam['course_name']}: {hidden_exam['grade']} ({hidden_exam['ects_credits']} ECTS)")
            
            print(f"\nVantaggi per la privacy:")
            print(f"  • Lo studente mantiene il controllo sulle informazioni sensibili")
            print(f"  • Solo i dati necessari vengono condivisi per il riconoscimento crediti")
            print(f"  • La prova crittografica garantisce autenticità")
            print(f"  • L'università non può accedere ai campi nascosti")
            
        else:
            print(f"Alcune prove non hanno superato la verifica!")
            
    except Exception as e:
        print(f"Errore nella demo divulgazione selettiva: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    """Esecuzione diretta: demo completo della divulgazione selettiva"""
    print("MERKLE CREDENTIALS")
    print("==============================")
    print()
    
    # Esegui direttamente la demo della divulgazione selettiva senza menu
    demo_selective_disclosure()