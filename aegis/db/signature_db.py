import sqlite3
from pathlib import Path
from typing import Optional
from aegis.logger.logger import get_logger

class SignatureDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.logger = get_logger()
        self._init_db()

    
    def _init_db (self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS signatures(
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash_type      TEXT NOT NULL,
                    hash_value     TEXT NOT NULL UNIQUE,
                    malware_name   TEXT NOT NULL,
                    severity       INTEGER DEFAULT 1
                )
            """)
            conn.execute ("""
                CREATE INDEX IF NOT EXISTS idx_hash_value
                ON signatures (hash_value)
            """)
            self.logger.info(f"Base de signatures initialisée : {self.db_path}")
    

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)
    
    def add_signature(
            self,
            hash_type: str,
            hash_value: str,
            malware_name: str,
            severity: int = 1
    ) -> bool:
        try:
            with self._connect() as conn:
                conn.execute(
                    """ INSERT INTO signatures
                            (hash_type, hash_value, malware_name, severity)
                            VALUES (?, ?, ?, ?) """,

                            (hash_type, hash_value.lower(), malware_name, severity)
                )
            return True
        except sqlite3.IntegrityError:
            self.logger.debug (f"Signature déjà présente: {hash_value}")
            return False

    def lookup (self, hash_value: str) -> Optional[dict]:

        with self._connect() as conn:

            cursor = conn.execute(

                "SELECT hash_type, hash_value, malware_name, severity "
                "FROM signatures WHERE hash_value = ?",
                (hash_value.lower(),)
            )
            
            row = cursor.fetchone()

        if row is None:
            return None
            
        return{
            "hash_type": row[0],
            "hash_value": row[1],
            "malware_name": row[2],
            "severity": row[3]
        }
    
    def count (self) -> int:

        with self._connect () as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM signatures")
            return cursor.fetchone()[0]
        
    def remove_signature(self, hash_value: str) -> bool:

        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM signatures WHERE hash_value = ?",
                (hash_value.lower(),)
            )
            return cursor.rowcount > 0

    def get_all_hashes(self) -> list:
        with self._connect() as conn:
            cursor = conn.execute("SELECT hash_value FROM signatures")
            return [row[0] for row in cursor.fetchall()]
        
            
