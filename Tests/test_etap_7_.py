from pathlib import Path
from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.quarantine.manager import QuarantineManager


print("\n\n\n")

config = Config.from_yaml("config.yaml")
setup_logger(config)

qm = QuarantineManager(config)

# Crée un fichier de test à mettre en quarantaine
test_file = Path("Tests/test_files/a_quarantiner.exe")
test_file.write_text("fichier de test")


# Test 1 — mise en quarantaine
qid = qm.quarantine(test_file, malware_name="FakeTrojan", severity=3)
print(f"ID quarantaine : {qid}")          # UUID
print(f"Fichier existe encore : {test_file.exists()}")  # False


# Test 2 — liste
items = qm.list_quarantined()

print(f"\nEn quarantaine : {len(items)}")   # 1
print(items[0]["malware_name"])           # FakeTrojan

# Test 3 — restauration
restored = qm.restore(qid)
print(f"Restauré : {restored}")                        # True
print(f"Fichier de retour : {test_file.exists()}")     # True

# Test 4 — suppression définitive
qid2 = qm.quarantine(test_file, malware_name="FakeTrojan", severity=3)
deleted = qm.delete(qid2)
print(f"Supprimé : {deleted}")            # True
print(f"Liste vide : {qm.list_quarantined()}")  # []
