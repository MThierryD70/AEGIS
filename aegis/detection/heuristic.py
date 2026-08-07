import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple
from aegis.logger.logger import get_logger


# Seuil d'entropie au-delà duquel un exécutable est jugé « dense »
# (contenu compressé/chiffré). Ne s'applique qu'aux fichiers PE : les formats
# déjà compressés (PDF, PNG, ZIP...) ont naturellement une entropie très
# élevée et ne doivent jamais être analysés ainsi.
ENTROPY_THRESHOLD = 7.0

# Nombre d'octets lus pour estimer l'entropie (échantillon = rapide et léger)
ENTROPY_SAMPLE_SIZE = 4 * 1024 * 1024  # 4 Mo

# Score minimal pour qualifier un fichier de « suspect ». Exiger au moins
# ~1.0 oblige à combiner plusieurs indicateurs et élimine la plupart des
# faux positifs (un simple exécutable dense mais légitime reste propre).
SUSPICIOUS_SCORE_THRESHOLD = 1.0

# Poids de chaque indicateur heuristique
WEIGHT_ENTROPY = 0.4
WEIGHT_PACKED = 0.5
WEIGHT_RWX_SECTION = 0.5
WEIGHT_SUSPICIOUS_IMPORTS = 0.6

# Imports PE considérés suspects par combinaison

SUSPICIOUS_IMPORTS = [
    {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"},
    {"CryptEncrypt", "InternetConnect"},
    {"RegSetValueEx", "ShellExecute", "DownloadFile"},
]

# Noms de sections typiques des packers (UPX, ASPack, NSPack, Petite...)
PACKED_SECTION_NAMES = {"UPX0", "UPX1", "UPX2", ".packed", ".aspack", ".nsp0", ".petite"}

# Droits de section PE (IMAGE_SCN_MEM_*)
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000

# Extensions analysées par l'heuristique (analyse PE uniquement)
PE_EXTENSIONS = {".exe", ".dll"}


@dataclass
class HeuristicResult:
    is_suspicious: bool
    score: float = 0.0
    indicators: List[str] = field(default_factory=list)

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

        # L'heuristique PE ne s'applique qu'aux exécutables : un PDF ou une
        # image n'est jamais « suspect » par la seule entropie.
        if path.suffix.lower() not in PE_EXTENSIONS:
            return HeuristicResult(is_suspicious=False, score=0.0)

        # Analyse 1 - entropie (uniquement pour les fichiers PE)
        entropy = self._compute_entropy(path)
        if entropy is not None:
            if entropy >= ENTROPY_THRESHOLD:
                indicators.append(f" entropie élevée {entropy:.2f}")
                score += WEIGHT_ENTROPY
            self.logger.debug(f" Entropie {path.name} : {entropy:.2f}")

        # Analyse 2 - caractéristiques PE (packing, sections, imports)
        for desc, weight in self._analyze_pe(path):
            indicators.append(desc)
            score += weight

        is_suspicious = score >= SUSPICIOUS_SCORE_THRESHOLD

        return HeuristicResult(
            is_suspicious=is_suspicious,
            score=round(score, 2),
            indicators=indicators
        )

    def _compute_entropy(self, path: Path) -> float:
        """Entropie de Shannon sur un échantillon (1 seule passe)."""
        try:
            with open(path, "rb") as f:
                data = f.read(ENTROPY_SAMPLE_SIZE)

            if not data:
                return 0.0

            frequencies = [0] * 256
            for byte in data:
                frequencies[byte] += 1

            size = len(data)
            entropy = 0.0
            for count in frequencies:
                if count:
                    p = count / size
                    entropy -= p * math.log2(p)

            return entropy
        except (PermissionError, OSError) as e:
            self.logger.warning(f" Impossible de lire {path} pour entropie : {e}")
            return None

    def _analyze_pe(self, path: Path) -> List[Tuple[str, float]]:
        """Indicateurs PE : packing, sections RWX et imports suspects.

        Retourne une liste de couples (description, poids).
        """
        indicators = []

        try:
            import pefile
            pe = pefile.PE(str(path))
        except Exception as e:
            self.logger.debug(f" Analyse PE ignorée pour {path.name} : {e}")
            return indicators

        # --- Packing (UPX ou point d'entrée dans la dernière section) ---
        if hasattr(pe, "OPTIONAL_HEADER") and pe.sections:
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            section_names = {
                s.Name.rstrip(b"\x00").decode("utf-8", errors="ignore")
                for s in pe.sections
            }
            packed = bool(section_names & PACKED_SECTION_NAMES)

            if not packed:
                last = pe.sections[-1]
                section_span = max(last.Misc_VirtualSize, last.SizeOfRawData)
                packed = last.VirtualAddress <= ep < last.VirtualAddress + section_span

            if packed:
                indicators.append(
                    (" exécutable packé (UPX / point d'entrée anormal)",
                     WEIGHT_PACKED)
                )

        # --- Section exécutable + lecture + écriture (RWX) ---
        for section in pe.sections:
            characteristics = section.Characteristics
            if (
                characteristics & IMAGE_SCN_MEM_EXECUTE
                and characteristics & IMAGE_SCN_MEM_WRITE
                and characteristics & IMAGE_SCN_MEM_READ
            ):
                name = section.Name.rstrip(b"\x00").decode("utf-8", errors="ignore")
                indicators.append((f" section RWX ({name})", WEIGHT_RWX_SECTION))
                break

        # --- Combinaisons d'imports suspects ---
        imports = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imports.add(imp.name.decode("utf-8", errors="ignore"))

        for suspicious_set in SUSPICIOUS_IMPORTS:
            if suspicious_set.issubset(imports):
                indicators.append(
                    (f" imports suspects : {suspicious_set}",
                     WEIGHT_SUSPICIOUS_IMPORTS)
                )
                break

        return indicators
