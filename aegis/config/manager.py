import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import List

@dataclass
class ScannerConfig:
    extensions: List[str] = field(default_factory=lambda: [".exe", ".dll"])
    max_file_size_mb: int = 100
    exclude_paths: List[str] = field(default_factory=list)

@dataclass
class DatabaseConfig:
    path: str = "./data/signatures.db"

@dataclass
class QuarantineConfig:
    dir: str = "./quarantine"
    encrypt: bool = False

@dataclass
class LoggingConfig:
    level : str = "INFO"
    file: str = "./logs/aegis.log"

@dataclass
class Config:
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    quarantine: QuarantineConfig = field(default_factory=QuarantineConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


    @classmethod
    def from_yaml (cls, path: str = "config.yaml") -> "Config":
        config_path = Path(path)

        if not config_path.exists():
            print(f"[Config] Fichier '{path}' introuvable. Valeurs par défaut utilisées.")
            return cls()
        
        with open (config_path, "r", encoding = "utf-8") as f:
            data = yaml.safe_load(f) or {}

        scanner_data = data.get("scanner", {})
        db_data = data.get("database", {})
        quarantine_data = data.get("quarantine", {})
        logging_data = data.get("logging", {})

        return cls (
            scanner=ScannerConfig(**scanner_data),
            database=DatabaseConfig(**db_data),
            quarantine=QuarantineConfig(**quarantine_data),
            logging= LoggingConfig(**logging_data),
        )
        