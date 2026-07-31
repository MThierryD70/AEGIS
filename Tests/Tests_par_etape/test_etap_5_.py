from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.db.signature_db import SignatureDB
from aegis.detection.signature_matcher import SignatureMatcher
from aegis.scanner.hasher import HashCalculator
from pathlib import Path


config = Config.from_yaml("config.yaml")
setup_logger(config)


db = SignatureDB(config.database.path)
matcher = SignatureMatcher(db)



# Test 1 — fichier EICAR (déjà en base depuis l'étape 4)

hashes = HashCalculator.compute(Path("Tests/test_files/eicar.com"))
result = matcher.check(hashes)

print("\n\n\n",result.is_threat,"\n")      # True
print(result.malware_name,"\n")   # EICAR-Test-File
print(result.severity,"\n")       # 4
print(result,"\n")                # MENACE détectée : EICAR-Test-File (sévérité 4/4) via sha256



# Test 2 — fichier sain (un de tes fichiers de test normaux)

hashes_sain = HashCalculator.compute(Path("Tests/test_files/programme.exe"))
result_sain = matcher.check(hashes_sain)
print("\n\n\n",result_sain.is_threat,"\n") # False
print(result_sain,"\n")           # Propre





# Test 3 — hashes vides
result_vide = matcher.check({})
print("\n\n\n",result_vide.is_threat, "\n\n") # False