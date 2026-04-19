import sqlite3
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional
from aegis.config.manager import Config
from aegis.logger.logger import get_logger


class QuarantineManager:
    def __init__(self, config: Config):
        self.quarantine_dir = Path(config.quarantine.dir)
        self.db_path = self.quarantine_dir / "quarantine.db"
        self.logger = get_logger()
        self._init()
        
    def _init(self):
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        with self._connect () as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantine (
                         id               TEXT PRIMARY KEY,
                         original_path    TEXT NOT NULL,
                         quarantine_path  TEXT NOT NULL,
                         malware_name     TEXT,
                         severity         INTEGER,
                         date_quarantined TEXT NOT NULL
                )
            """)
            
        
        self.logger.info (f" Quarantaine initialisée : {self.quarantine_dir}")

    def _connect (self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)
    
    def quarantine (self, path: Path, malware_name: str, severity : int) -> Optional [str]:
        if not path.exists():
            self.logger.error(f" Fichier introuvable pour la quarantaine: {path}")
            return None
        
        quarantine_id = str (uuid.uuid4())
        dest = self.quarantine_dir / f" {self.quarantine_dir}.quar"

        try:
            shutil.move(str(path), str(dest))
        except (PermissionError, OSError) as e:
            self.logger.error (f" Impossible de déplacer {path} : {e}")
            return None
        
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO quarantine
                         (id, original_path, quarantine_path, malware_name, severity, date_quarantined)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                quarantine_id,
                str (path.resolve()),
                str(dest),
                malware_name,
                severity,
                datetime.now().isoformat()
            )
        )
        
        self.logger.warning(
            f" Fichier mis en quarantaine: {path.name} -> {quarantine_id}"
        )

        return quarantine_id
    
    def restore (self, quarantine_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                " SELECT original_path, quarantine_path FROM quarantine WHERE id = ?",
                (quarantine_id,)
            )
            row = cursor.fetchone()



        if row is None:
            self.logger.error(f"ID introuvable en quarantaine : {quarantine_id}")
            return False


        if row is None:
            self.logger.error (f" ID introuvable en quarantine : {quarantine_id}")
            return False
        original_path, quarantine_path = Path(row[0]), Path(row[1])
        if not quarantine_path.exists():
            self.logger.error(f" Fichier quarantaine manquant : {quarantine_path}")
            return False
        try:
            original_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(quarantine_path), str(original_path))
        except (PermissionError, OSError) as e:
            self.logger.error (f" Impossible de restaurer {quarantine_id} : {e}")
            return False        
        with self._connect() as conn:
            conn.execute(" DELETE FROM quarantine WHERE id = ?", (quarantine_id,))     
        self.logger.info(f" Fichier restauré : {original_path}")
        return True
    
    def list_quarantined (self) -> list:
        
        with self._connect() as conn:
            cursor = conn.execute(
                " SELECT id, original_path, malware_name, severity, date_quarantined "
                "FROM quarantine ORDER BY date_quarantined DESC"
            )

            rows = cursor.fetchall()
            
        return [
            {
                "id": row[0],
                "original_path": row[1],
                "malware_name": row[2],
                "severity": row[3],
                "date_quarantined": row[4] 
            }

            for row in rows
        ]

    
    def delete (self, quarantine_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "SELECT quarantine_path FROM quarantine WHERE id = ?", (quarantine_id,)
            )

            row = cursor.fetchone()

            if row is None:
                self.logger.error(f" ID introuvable : {quarantine_id}")
                return False
            
            quarantine_path = Path(row[0])
            if quarantine_path.exists():
                quarantine_path.unlink()
            
            with self._connect() as conn:
                conn.execute(" DELETE FROM quarantine WHERE id = ?", (quarantine_id,))

            self.logger.info(f" Fichier supprimé définitivelent: {quarantine_id}")
            return True
        
