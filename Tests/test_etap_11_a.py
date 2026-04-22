from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.updater.updater import Updater


print("\n\n\n")

config = Config.from_yaml("config.yaml")
setup_logger(config)

updater = Updater(config)

# Test 1 — statut avant import
status = updater.status()
print(f"\n\n Signatures avant : {status['total_signatures']}\n")

# Test 2 — import depuis fichier local
result = updater.import_from_file("data/sample_signatures.json")
print(f"\n\nAjoutées : {result['added']}")
print(f"\nDoublons : {result['skipped']}\n")

# Test 3 — deuxième import du même fichier (tout doit être doublon)
result2 = updater.import_from_file("data/sample_signatures.json")
print(f"\nDoublons au 2ème import : {result2['skipped']}")

# Test 4 — statut après import
status2 = updater.status()
print(f"\n\nSignatures après : {status2['total_signatures']}\n\n")