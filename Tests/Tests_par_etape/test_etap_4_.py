from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.db.signature_db import SignatureDB

config = Config.from_yaml("config.yaml")
setup_logger(config)

db = SignatureDB(config.database.path)



# Test 1 — ajout de la signature EICAR

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
added = db.add_signature("sha256", EICAR_SHA256, "EICAR-Test-File", severity=4)
print(f"\nAjouté : {added}\n")        # True




# Test 2 — doublon refusé silencieusement

added_again = db.add_signature("sha256", EICAR_SHA256, "EICAR-Test-File", severity=4)
print(f"\nDoublon : {added_again}\n") # False



# Test 3 — lookup positif

result = db.lookup(EICAR_SHA256)
print("\n",result,"\n")
# {"hash_type": "sha256", "hash_value": "275a...", "malware_name": "EICAR-Test-File", "severity": 4}



# Test 4 — lookup négatif (hash inconnu)

result_vide = db.lookup("hashquinexistepas")
print("\n",result_vide,"\n")                # None



# Test 5 — comptage
print(f"\nSignatures en base : {db.count()}\n")  # 1