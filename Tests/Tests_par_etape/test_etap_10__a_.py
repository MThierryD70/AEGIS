
# Test 1 — entropie sur des fichiers normaux 


from pathlib import Path
from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.detection.heuristic import HeuristicAnalyzer

print("\n\n\n")

config = Config.from_yaml("config.yaml")
setup_logger(config)

analyzer = HeuristicAnalyzer()

# Fichier texte normal → entropie basse
result = analyzer.analyze(Path("tests/test_files/script.js"))
print(f"\n\n script.js     : {result}\n")

# Fichier EICAR → entropie moyenne
result = analyzer.analyze(Path("tests/test_files/eicar.com"))
print(f"\n\neicar.com     : {result}\n\n")





# Test 2 — crée un fichier à haute entropie :


import os

# Génère 10 Ko d'octets aléatoires → entropie maximale (~8.0)

random_bytes = os.urandom(10240)

with open("tests/test_files/suspect.exe", "wb") as f:
    f.write(random_bytes)

result = analyzer.analyze(Path("tests/test_files/suspect.exe"))

print(f"\n\nsuspect.exe   : {result}\n\n")

# Doit afficher SUSPECT avec entropie élevée