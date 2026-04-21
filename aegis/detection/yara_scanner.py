from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from aegis.logger.logger import get_logger


@dataclass
class YaraResult:

    is_threat: bool
    matched_rules: List [str] = field(default_factory=list)
    severity: Optional [str] = None


    def __str__(self):
        if not self.is_threat:
            return "Aucune règle YARA déclenchée"
        return f" YARA : {', '.join(self.matched_rules)}"





class YaraScanner:
    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.logger = get_logger()
        self.rules = self._loaded_rules()
    
    def _loaded_rules(self):
        try:
            import yara

            yara_files = list (self.rules_dir.glob("*.yar"))

            if not yara_files:
                self.logger.warning(f" Aucune règle YARA trouvée dans {self.rules_dir}")
                return None
            
            # Compile toutes les règles en une seule fois

            filepaths = {f.stem: str(f) for f in yara_files}
            rules = yara.compile(filepaths=filepaths)
            self.logger.info(f"{len(yara_files)} fichier(s) de règles YARA chergé(s)")
            return rules
        except ImportError:
            self.logger.warning("yara-python non installée - scan YARA désactivé")
            return None
        except Exception as e:
            self.logger.error(f" Erreur chargement règles YARA : {e}")
            return None
        
    
    def scan (self, path : Path) -> YaraResult:
        if self.rules is None:
            return YaraResult(is_threat=False)
        
        try:
            matches = self.rules.match(str(path))

            if not matches:
                return YaraResult(is_threat=False)
            matched_rules = [match.rule for match in matches]
            severity = matches[0].meta.get("severity", "medium")

            self.logger.warning(
                f" Règle(s) YARA déclenchée(s) sur {path.name}: "
                f"{', '.join(matched_rules)}"
            )

            return YaraResult(
                is_threat=True,
                matched_rules=matched_rules,
                severity=severity
            )
        except Exception as e:
            self.logger.error(f" Erreur scan YARA sur {path} : {e}")
            return YaraResult(is_threat=False)
        