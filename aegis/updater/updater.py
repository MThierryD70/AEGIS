import json
import hashlib
from pathlib import Path
from typing import Optional
from aegis.config.manager import Config
from aegis.db.signature_db import SignatureDB
from aegis.logger.logger import get_logger



class Updater:
    def __init__(self, config : Config):
        self.config = config
        self.db = SignatureDB(config.database.path)
        self.logger = get_logger ()



    def import_from_file (self, json_path: str)-> dict:
        
        path = Path(json_path)

        if not path.exists():
            self.logger.error(f" Fichier introuvable : {json_path}")
            return {"success": False, "added": 0, "skipped": 0, "errors": 0}
        
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            self.logger.error(f" Fichier JSON introuvable: {e}")
            return {"success": False, "added": 0, "skipped": 0, "errors": 0}
        
        signatures = data.get("signatures", [])

        version = data.get("version", "inconnue")

        self.logger.info(

            f" Import signatures version {version} "
            f" ({len(signatures)} entrée(s))"
        )

        added = skipped = errors = 0

        for sig in signatures:
            try:
                success = self.db.add_signature(
                    hash_type = sig["hash_type"],
                    hash_value = sig["hash_value"],
                    malware_name = sig["malware_name"],
                    severity = sig.get("severity", 1)
                )

                if success:
                    added +=1
                else:
                    skipped += 1
            except KeyError as e:
                self.logger.warning(f" Signature malformée, champ manquant: {e}")
                errors += 1
        
        self.logger.info(
            f" \n\nImport terminée - {added} ajoutée(s), "
            f" {skipped} ignorée(s) (doublon), {errors} erreur(s)"
        )
        return {"success": True, "added": added, "skipped": skipped, "errors": errors}
    

    def impory_from_url(self, url: str) -> dict:
        try:
            import httpx
        except ImportError:
            self.logger.error(" httpx non installé - pip install hattpx")
            return {"success": False, "added": 0, "skipped": 0, "errors": 0}
        
        self.logger.info(f" Téléchargement des signatures depuis : {url}")

        try:

            # Téléchargement de signatures

            response = httpx.get(url, timeout=30)
            response.raise_for_status()
            content = response.content

            # Vérifie l'intégrité si un fichier .sha256 existe
            checksum_url = url + ".sha256"

            try:
                checksum_response = httpx.get(checksum_url, timeout=10)
                if checksum_response.status_code == 200:
                    excepted_hash = checksum_response.text.strip().lower()
                    actual_hash = hashlib.sha256(content).hexdigest()

                    if actual_hash != excepted_hash:
                        self.logger.error(
                            f" Vérification d'intégrité échoue -"
                            f" attendu: {excepted_hash[:16]}..."
                            f" obtenu: {actual_hash[:16]}..."
                        )

                        return {"success": False, "added": 0, "skipped": 0, "errors": 0}
                    self.logger.info(" Intégrité vérifié avec succès")
            except:
                self.logger.info("Pas de fichier .sha256 troouvée, intégrité non vérifié")


            # Sauvegarde temoraire et import
            tmp_path = Path("data/tmp_updater.json")
            tmp_path.write_bytes(content)
            result = self.import_from_file(str(tmp_path))
            tmp_path.unlink()
            return result
                
        except Exception as e:
            self.logger.error (f" Erreur téléchargement: {e}")
            return {"success": False, "added": 0, "skipped": 0, "errors": 0}



    def status(self) -> dict:
        count = self.db.count()
        return{
            "total_signatures": count,
            "database_path": self.config.database.path
        }
