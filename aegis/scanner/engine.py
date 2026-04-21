import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from aegis.config.manager import Config
from aegis.logger.logger import get_logger
from aegis.scanner.walker import FileWalker
from aegis.scanner.hasher import HashCalculator
from aegis.db.signature_db import SignatureDB
from aegis.detection.signature_matcher import SignatureMatcher, MatchResult

from aegis.detection.heuristic import HeuristicAnalyzer, HeuristicResult
from aegis.detection.yara_scanner import YaraScanner, YaraResult



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
        self.matcher = SignatureMatcher(self.db)

        self.heuristic = HeuristicAnalyzer()
        self.yara_scanner = YaraScanner("data/yara_rules")






    def scan (self, path: str) -> ScanReport:
        self.logger.info (f" Démarrage du scan : {path}")
        report = ScanReport()
        start = time.perf_counter()

        for file_path in self.walker.walk(path):
            result = self._analyze (file_path)
            report.results.append(result)
            if result.is_threat:
                self.logger.warning(
                    f" [!] MENACE : {result.match_result.malware_name} "
                    f" ->  {file_path}"
                )
            else:
                self.logger.debug(f" Propre: {file_path}")
        report.duration_seconds = time.perf_counter() - start
        self.logger.info(str(report))
        return report
    
    def _analyze(self, path: Path) -> FileResult:
        hashes = HashCalculator.compute (path)

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

