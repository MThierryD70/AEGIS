from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from aegis.logger.logger import get_logger


# Sévérités YARA considérées comme une MENACE confirmée. Les règles
# génériques/heuristiques (medium, low, info) sont simplement enregistrées et
# ne déclenchent pas d'alerte : une règle trop large ne doit pas faire
# remonter des dizaines de faux positifs.
THREAT_SEVERITIES = {"critical", "high"}

@dataclass
class YaraResult:
    is_threat: bool
    matched_rules: List[str] = field(default_factory=list)
    severity: Optional[str] = None

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

            yara_files = list(self.rules_dir.glob("*.yar"))

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


    def scan(self, path: Path) -> YaraResult:
        if self.rules is None:
            return YaraResult(is_threat=False)

        try:
            # L'API C de YARA utilise la codepage ANSI sur Windows : les
            # chemins accentués (é, è...) y sont illisibles. On passe donc
            # toujours les octets directement, ce qui évite l'échec puis le
            # fallback (et la relecture du fichier qui l'accompagnait).
            with open(path, "rb") as f:
                matches = self.rules.match(data=f.read())
        except Exception as e:
            self.logger.error(f" Erreur scan YARA sur {path} : {e}")
            return YaraResult(is_threat=False)

        if not matches:
            return YaraResult(is_threat=False)

        matched_rules = [match.rule for match in matches]
        severity = matches[0].meta.get("severity", "medium")
        is_threat = severity.lower() in THREAT_SEVERITIES

        if is_threat:
            self.logger.warning(
                f" YARA : {', '.join(matched_rules)} sur {path.name} "
                f"(sévérité {severity})"
            )
        else:
            self.logger.info(
                f" YARA (info) : {', '.join(matched_rules)} sur {path.name} "
                f"(sévérité {severity})"
            )

        return YaraResult(
            is_threat=is_threat,
            matched_rules=matched_rules,
            severity=severity
        )
    