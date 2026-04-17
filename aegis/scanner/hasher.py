import hashlib
from pathlib import Path
from typing import Optional
from aegis.logger.logger import get_logger

BLOCK_SIZE = 65536 # 64 ko

class HashCalculator:

    @staticmethod
    def compute (path: Path) -> Optional [dict]:
        logger = get_logger()
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()

        try:
            with open (path, "rb") as f:

                while chunk := f.read(BLOCK_SIZE):
                    md5.update(chunk)
                    sha256.update(chunk)
            return {
                "md5" : md5.hexdigest(),
                "sha256" : sha256.hexdigest()
            }
        except PermissionError:
            logger.warning(f"Permission refusée pour le hash : {path}")
            return None
        
        except OSError as e:
            logger.error(f"Erreur lecture du fichier {path} : {e}")
            return None
    