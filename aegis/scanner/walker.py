from pathlib import Path
from typing import Generator
from aegis.config.manager import Config
from aegis.logger.logger import get_logger

class FileWalker:
    def __init__(self, config: Config):
        self.extensions = set(config.scanner.extensions)
        self.max_size_bytes = config.scanner.max_file_size_mb * 1024 * 1024
        self.exclude_paths = set(
            str(Path(p).resolve()) for p in config.scanner.exclude_paths
        )
        self.logger = get_logger()
    
    def walk (self, root: str) -> Generator [Path, None, None]:
        root_path = Path(root).resolve()

        if not root_path.exists():
            self.logger.error(f"Chemin introuvable: {root_path}")
            return
        
        # Cas fichier unique
        if root_path.is_file():
            if self.should_scan(root_path):
                yield root_path
            return

        # Cas repertoire
        for path in root_path.rglob("*"):
            if not path .is_file():
                continue
            if self._is_excluded(path):
                self.logger.debug(f"Exclu : {path}")
                continue
            if not self._should_scan (path):
                continue
            yield path

    def _should_scan (self, path: Path) -> bool:
        # Vérifie l'extension
        if path.suffix.lower() not in self.extensions:
            return False
        # Vérifie la taille
        try:
            if path.stat().st_size > self.max_size_bytes:
                self.logger.warning(f" Fichier trop volumineux, ignoré: {path}")
                return False
        except PermissionError:
            self.logger.warning(f"Permission refusée: {path}")
            return False
        return True
        
    def _is_excluded (self, path: Path) -> bool:
        resolved = str (path.resolve())
        return any (resolved.startswith(excluded) for excluded in self.exclude_paths)
        
