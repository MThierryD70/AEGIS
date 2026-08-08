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
    
    def import_from_url(self, url: str) -> dict:
        try:
            import httpx
        except ImportError:
            self.logger.error("httpx non installé — pip install httpx")
            return {"success": False, "added": 0, "skipped": 0, "errors": 0}

        self.logger.info(f"Téléchargement des signatures depuis : {url}")

        try:
            response = httpx.get(url, timeout=60, follow_redirects=True)
            response.raise_for_status()
            content = response.text

            # Vérification d'intégrité SHA-256 si disponible
            checksum_url = url + ".sha256"
            try:
                checksum_response = httpx.get(checksum_url, timeout=10)
                if checksum_response.status_code == 200:
                    import hashlib
                    expected = checksum_response.text.strip().lower()
                    actual   = hashlib.sha256(content.encode()).hexdigest()
                    if actual != expected:
                        self.logger.error("Vérification d'intégrité échouée")
                        return {"success": False, "added": 0, "skipped": 0, "errors": 0}
                    self.logger.info("Intégrité vérifiée avec succès")
            except Exception:
                self.logger.warning("Pas de fichier .sha256 trouvé — intégrité non vérifiée")

            # Détection automatique du format
            stripped = content.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                # Format JSON direct
                import json
                data = json.loads(stripped)
            elif stripped.startswith("#") or "," in stripped[:200]:
                # Format CSV — détecte MalwareBazaar et similaires
                self.logger.info("Format CSV détecté — conversion en cours...")
                data = self._convert_malware_signature_list_csv_to_json(content)
                self.logger.info(
                    f"Conversion terminée : {len(data['signatures'])} entrée(s)"
                )
            else:
                self.logger.error(f"Format non reconnu")
                return {"success": False, "added": 0, "skipped": 0, "errors": 0}

            # Sauvegarde temporaire et import
            import json
            from pathlib import Path
            tmp_path = Path("data/tmp_update.json")
            tmp_path.parent.mkdir(exist_ok=True)
            tmp_path.write_text(
                json.dumps(data, ensure_ascii=False), encoding="utf-8"
            )
            result = self.import_from_file(str(tmp_path))
            tmp_path.unlink(missing_ok=True)
            return result

        except Exception as e:
            self.logger.error(f"Erreur téléchargement : {e}")
            return {"success": False, "added": 0, "skipped": 0, "errors": 0}


    def _convert_malware_signature_list_csv_to_json(self, content: str) -> dict:
        """Convertit le CSV MalwareBazaar au format JSON AEGIS."""
        from datetime import datetime
        output = {
            "version": datetime.now().strftime("%Y.%m.%d"),
            "signatures": []
        }

        for line in content.splitlines():
            if line.startswith("#") or not line.strip():
                continue

            parts = line.replace('"', '').split(',')
            if len(parts) < 3:
                continue

            sha256_value = parts[1].strip()
            md5_value    = parts[2].strip()
            malware_name = (
                parts[7].strip()
                if len(parts) > 7 and parts[7].strip()
                else "MalwareBazaar.Generic"
            )

            if sha256_value and sha256_value.lower() != "null":
                output["signatures"].append({
                    "hash_type":    "sha256",
                    "hash_value":   sha256_value,
                    "malware_name": malware_name,
                    "severity":     4
                })

            if md5_value and md5_value.lower() != "null":
                output["signatures"].append({
                    "hash_type":    "md5",
                    "hash_value":   md5_value,
                    "malware_name": f"{malware_name}-MD5",
                    "severity":     4
                })
        return output

    def status(self) -> dict:
        count = self.db.count()
        return{
            "total_signatures": count,
            "database_path": self.config.database.path
        }
