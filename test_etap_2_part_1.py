from aegis.config.manager import Config
from aegis.logger.logger import setup_logger, get_logger

# Setup unique au démarrage
config = Config.from_yaml("config.yaml")
logger = setup_logger(config)

# Utilisation depuis n'importe où
log = get_logger()
log.debug("Message debug")     # invisible si level=INFO
log.info("Antivirus démarré")  # visible
log.warning("Fichier suspect") # visible
log.error("Erreur critique")   # visible