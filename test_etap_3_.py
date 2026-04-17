# Test 1 : Calcul hash d'un fichier réel

from pathlib import Path
from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.scanner.hasher import HashCalculator


config = Config.from_yaml("config.yaml")
setup_logger(config)

# Calcule le hash d'un de tes fichiers de test

hashes = HashCalculator.compute(Path("Tests/test_files/programme.exe"))

print("\n",hashes,"\n")
# {"md5": "...", "sha256": "..."}



# Test 2 : Vérification de la chérence

# Le même fichier doit toujours donner le même hash
hashes1 = HashCalculator.compute(Path("Tests/test_files/programme.exe"))
hashes2 = HashCalculator.compute(Path("Tests/test_files/programme.exe"))
print("\n",hashes1 == hashes2,"\n")  # doit afficher True



# Test 3 : Le fichier eicar
hashes = HashCalculator.compute(Path("Tests/test_files/eicar.com"))
print("\n Sha256 du fichier eicar calculé: ", hashes["sha256"] ,"\n")
#print(hashes)

print("\n Sha256 connu du fichier eicar:  275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")

