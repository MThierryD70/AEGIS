from dataclasses import dataclass
from typing import Optional
from aegis.db.signature_db import SignatureDB
from aegis.logger.logger import get_logger


@dataclass
class MatchResult:
    is_threat: bool
    malware_name: Optional[str] = None
    severity: Optional[int] = None
    matched_hash: Optional[str] = None
    hash_type: Optional[str] = None


    def __str__(self):
        if not self.is_threat:
            return "Propre"
        return (
            f"[!] MENACE dectectée : {self.malware_name}"
            f" (Sévérité {self.severity}/4)"
            f" Via {self.hash_type}"
        )

class SignatureMatcher:
    def __init__(self, db: SignatureDB):
        self.db = db
        self.logger = get_logger()

    
    def check (self, hashes: dict) -> MatchResult:
        if not hashes:
            return MatchResult(is_threat=False)
        
        for hash_type, hash_value in hashes.items():

            result = self.db.lookup(hash_value)

            if result is not None:
                self.logger.warning(
                    f"Signature trouvée: {result['malware_name']}"
                    f"({hash_type}: {hash_value[:16]}...)"
                )

                return MatchResult(
                    is_threat=True,
                    malware_name = result["malware_name"],
                    severity = result["severity"],
                    matched_hash= hash_value,
                    hash_type= hash_type
                )


            
        return MatchResult(is_threat=False)
