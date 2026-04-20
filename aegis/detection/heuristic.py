import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import List
from aegis.logger.logger import get_logger


# Seuil d'entropie au-delà duquel un fichier est suspect

ENTROPY_THRESHOLD = 7.0

# Imports PE considérés suspects par combinaison

SUSPICIOUS_IMPORTS = [
    {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"},
    {"CryptEncrypt", "InternetConnect"},
    {"RegSetValueEx", "ShellExcute", "DownloadFile"},
]


@dataclass
class HeuristicResult:
    is_suspicious: bool
    score: float = 0.0
    indicators: List [str] = field(default_factory=list)

    def __str__(self):
        if not self.is_suspicious:
            return f" Normal (score: {self.score:.2f})"
        
        return (
            f" SUSPECT (score: {self.score:.2f})"
            f"- {', '.join(self.indicators)}"
        )
    

class HeuristicAnalyzer:
    def __init__(self):
        self.logger = get_logger()
    
    def analyze(self, path: Path) -> HeuristicResult:
        indicators = []
        score = 0.0

        # Analyse 1 - entropie

        entropy = self._compute_entropy(path)
        if entropy is not None:
            if entropy >= ENTROPY_THRESHOLD:
                indicators.append(f" entropie élevée {entropy:.2f}")
                score += 0.5
            self.logger.debug(f" Entropie {path.name} : {entropy:.2f}")
        

        # Analyse 2 - import PE suspects (uniquement .exe et .dll)
        if path.suffix.lower() in {".exe", ".dll"}:
            suspicious_imports = self._check_pe_imports(path)
            if suspicious_imports:
                indicators.append(f" imports suspects : {suspicious_imports}")
                score += 0.5
        
        is_suspicious = score >= 0.5

        return HeuristicResult (
            is_suspicious = is_suspicious,
            score = round(score, 2),
            indicators=indicators
        )
    
    def _compute_entropy (self, path: Path) -> float:

        try:
            with open (path, "rb") as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            # Fréquence de chaque octet possible (0-255)
            frequencies = [data.count(bytes([b]))/len(data) for b in range(256)]

            # Formule de Shannon : H = - somme (p())*log2(p(x))
            entropy = - sum(
                p * math.log2(p)
                for p in frequencies
                if p > 0
            )

            return entropy
        except (PermissionError, OSError) as e:
            self.logger.warning(f" Impossible de lire {path} pour entropie : {e}")
            return None
        
    
    def _check_pe_imports(self, path: Path) -> str:
        try:
            import pefile
            pe = pefile.PE(str(path))

            # Récupère tous les noms d'imports su fichier
            imports = set()
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imports.add(imp.name.decode("utf-8", errors = "ignore"))
            

            # Vérifie si une combinaison suspecte est présente
            for suspicious_set in SUSPICIOUS_IMPORTS:
                if suspicious_set.issubset(imports):
                    return str(suspicious_set)
            
            return ""
        except Exception as e:
            self.logger.debug(f" Analyse PE ignorée pour {path.name} : {e}")
            return ""
                    
    
 
