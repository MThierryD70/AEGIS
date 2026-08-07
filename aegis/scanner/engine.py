import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from aegis.config.manager import Config
from aegis.logger.logger import get_logger, log_section, log_blank
from aegis.scanner.walker import FileWalker
from aegis.db.signature_db import SignatureDB

#from aegis.scanner.hasher import HashCalculator
#from aegis.detection.signature_matcher import SignatureMatcher
from aegis.detection.signature_matcher import MatchResult

from aegis.core.aegis_engine import AegisHasher, AegisBloomMatcher, log_status

from aegis.detection.heuristic import HeuristicAnalyzer, HeuristicResult
from aegis.detection.yara_scanner import YaraScanner, YaraResult

# Fréquence des messages de progression pendant le scan (en nb de fichiers).
# Le scan est silencieux entre les avertissements : ce compteur évite
# l'impression que le scan est bloqué sur un gros fichier.
PROGRESS_EVERY = 75


@dataclass
class FileResult:
    path: Path
    hashes: Optional[dict]
    match_result: MatchResult

    heuristic_result : HeuristicResult = None
    yara_result: YaraResult = None

    @property
    def is_threat (self) -> bool:
        sig_threat = self.match_result.is_threat
        yara_threat = self.yara_result is not None and self.yara_result.is_threat
        heuristic_threat = (
            self.heuristic_result is not None
            and self.heuristic_result.is_suspicious
        )
        return sig_threat or yara_threat or heuristic_threat

    @property
    def threat_name (self) -> Optional[str]:
        """Nom lisible de la menace, quelle que soit la source (signature,
        YARA ou heuristique)."""
        if self.match_result.is_threat:
            return self.match_result.malware_name or "Signature (inconnue)"
        if self.yara_result is not None and self.yara_result.is_threat:
            return ", ".join(self.yara_result.matched_rules) or "Règle YARA"
        if self.heuristic_result is not None and self.heuristic_result.is_suspicious:
            return "Heuristique"
        return None

    @property
    def threat_severity (self) -> Optional[str]:
        if self.match_result.is_threat:
            return str(self.match_result.severity)
        if self.yara_result is not None and self.yara_result.is_threat:
            return self.yara_result.severity
        if self.heuristic_result is not None and self.heuristic_result.is_suspicious:
            return "medium"
        return None
    



@dataclass
class ScanReport:
    results: List[FileResult] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def total_scanned(self) -> int:
        return len(self.results)
    @property
    def threats_found(self) -> int:
        return sum(1 for r in self.results if r.is_threat)
    
    @property
    def threats (self) -> List[FileResult]:
        return [r for r in self.results if r.is_threat]
    
    def __str__(self):
        return(
            f" Scan terminé en {self.duration_seconds:.2f}s - "
            f" {self.total_scanned} fichiers(s) analysé (s), "
            f" {self.threats_found} menace (s) détectée (s) "
        )



class ScannerEngine:
    def __init__(self, config: Config):
        self.config = config
        self.logger = get_logger()
        self.walker = FileWalker(config)
        self.db = SignatureDB(config.database.path)
        #self.matcher = SignatureMatcher(self.db)

        self.matcher = AegisBloomMatcher(self.db)

        self.heuristic = HeuristicAnalyzer()
        self.yara_scanner = YaraScanner("data/yara_rules")
        log_status()


    def scan(self, path: str) -> ScanReport:
        log_section(f"Scan — {path}")
        self.logger.info(f"Démarrage du scan : {path}")
        report = ScanReport()
        start = time.perf_counter()
        scanned = 0

        for file_path in self.walker.walk(path):
            result = self._analyze(file_path)
            report.results.append(result)
            scanned += 1

            if result.is_threat:
                self.logger.warning(
                    f"MENACE : {result.threat_name} "
                    f"→ {file_path}"
                )
            else:
                self.logger.debug(f"Propre : {file_path.name}")

            if scanned % PROGRESS_EVERY == 0:
                self.logger.info(
                    f"Progression : {scanned} fichier(s) analysé(s)"
                )

        report.duration_seconds = time.perf_counter() - start
        log_blank()
        self.logger.info(str(report))
        log_blank()
        return report    
    
    def _analyze(self, path: Path) -> FileResult:
        #hashes = HashCalculator.compute (path)
        hashes = AegisHasher.compute(path)

        if hashes is None:
            return FileResult(
                path = path,
                hashes = None,
                match_result = MatchResult(is_threat=False)
            )
        
        match_result = self.matcher.check(hashes)
        heuristic_result = self.heuristic.analyze(path)
        yara_result = self.yara_scanner.scan(path)

        return FileResult(
            path=path,
            hashes = hashes,
            match_result = match_result,
            heuristic_result=heuristic_result,
            yara_result=yara_result
        )  

