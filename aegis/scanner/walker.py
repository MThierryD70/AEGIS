import os
import platform
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

    def walk(self, root: str) -> Generator[Path, None, None]:
        root_path = Path(root).resolve()

        if not root_path.exists():
            self.logger.error(f"Chemin introuvable: {root_path}")
            return

        # Cas fichier unique
        if root_path.is_file():
            if self._should_scan(root_path, None):
                yield root_path
            return

        # Cas repertoire
        yield from self._walk_dir(root_path)

    def _walk_dir(self, dir_path: Path) -> Generator[Path, None, None]:
        """Énumération récursive via os.scandir : l'OS fournit les métadonnées
        (taille, type) gratuitement dans l'énumération, sans appel système
        supplémentaire par fichier. Évite aussi Path.resolve() par fichier,
        très lent sur OneDrive (reparse points « cloud »)."""
        try:
            entries = os.scandir(str(dir_path))
        except OSError as e:
            self.logger.debug(f"Scan refusé: {dir_path} ({e})")
            return

        with entries:
            for entry in entries:
                path = Path(entry.path)
                try:
                    is_file = entry.is_file()
                except OSError:
                    continue

                if not is_file:
                    yield from self._walk_dir(path)
                    continue

                if self._is_excluded(path):
                    self.logger.debug(f"Exclu : {path}")
                    continue
                if not self._should_scan(path, entry):
                    continue
                yield path

    def _should_scan(self, path: Path, entry=None) -> bool:
        # Vérifie l'extension
        if path.suffix.lower() not in self.extensions:
            return False
        # Vérifie la taille : on utilise le stat déjà fourni par scandir
        # (entry) et on rejette AVANT toute opération coûteuse.
        try:
            st = entry.stat() if entry is not None else path.stat()
        except OSError as e:
            self.logger.warning(f"Stat refusé: {path} ({e})")
            return False

        if st.st_size > self.max_size_bytes:
            self.logger.warning(f" Fichier trop volumineux, ignoré: {path}")
            return False

        # Alias d'exécution Windows (WindowsApps) : reparse point de taille 0,
        # illisible (Errno 22) - à ignorer. Uniquement pour les fichiers de
        # taille 0 : inutile de tester les autres.
        if st.st_size == 0 and self._is_windows_alias(path):
            self.logger.debug(f"Alias Windows ignoré: {path}")
            return False

        return True

    @staticmethod
    def _is_windows_alias(path: Path) -> bool:
        """Détecte les aliases d'exécution Windows (WindowsApps) : reparse
        points de taille 0. is_symlink() est peu fiable selon la version de
        Python, on utilise l'attribut FILE_ATTRIBUTE_REPARSE_POINT (0x400)."""
        if platform.system() != "Windows":
            return False
        try:
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            if attrs == 0xFFFFFFFF:  # INVALID_FILE_ATTRIBUTES
                return False
            return bool(attrs & 0x400)
        except Exception:
            return False

    def _is_excluded(self, path: Path) -> bool:
        # Optimisation : sans exclusions, aucun resolve() par fichier
        # (resolve() bloque sur les reparse points OneDrive).
        if not self.exclude_paths:
            return False
        resolved = str(path.resolve())
        return any(resolved.startswith(excluded) for excluded in self.exclude_paths)
