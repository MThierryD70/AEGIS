import logging
import sys
from pathlib import Path
from aegis.config.manager import Config

def setup_logger (config: Config) -> logging.Logger:
     logger = logging.getLogger("antivirus")
     logger.setLevel(getattr(logging, config.logging.level.upper(), logging.INFO))

     # Format commun aux handlers
     formatter = logging.Formatter(
          fmt= "%(asctime)s [%(levelname)s] %(message)s",
          datefmt="%Y-%m-%d %H:%M:%S"

     )

     # Handler 1 : affichage console

     console_handler = logging.StreamHandler(sys.stdout)
     console_handler.setFormatter(formatter)
     logger.addHandler(console_handler)


     # Handler 2 : écriture dans un fichier
     log_path = Path(config.logging.file)
     log_path.parent.mkdir(parents=True, exist_ok=True)
     file_handler = logging.FileHandler(log_path, encoding="utf-8")
     file_handler.setFormatter(formatter)
     logger.addHandler(file_handler)

     return logger

def get_logger() -> logging.Logger:
     return logging.getLogger("antivirus")


