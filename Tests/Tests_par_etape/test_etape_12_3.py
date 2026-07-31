import time
from pathlib import Path
from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.scanner.walker import FileWalker
from aegis.scanner.hasher import HashCalculator
from aegis.scanner.hasher_cpp import HashCalculatorCpp

print("\n\n")
config = Config.from_yaml("config.yaml")
setup_logger(config)

print("\n\n")
# Collecte d'abord tous les fichiers sans compter le temps de walk
walker = FileWalker(config)
bureau = r"C:\Users\DELL LATITUDE 5420\OneDrive\Bureau"
fichiers = list(walker.walk(bureau))
print(f"Fichiers à analyser : {len(fichiers)}")

if not fichiers:
    print("Aucun fichier trouvé — vérifie les extensions dans config.yaml")
else:
    # Mesure Python
    start = time.perf_counter()
    for f in fichiers:
        HashCalculator.compute(f)
    python_time = time.perf_counter() - start

    # Mesure C++
    start = time.perf_counter()
    for f in fichiers:
        HashCalculatorCpp.compute(f)
    cpp_time = time.perf_counter() - start

    print(f"Python  : {python_time:.3f}s")
    print(f"C++     : {cpp_time:.3f}s")
    print(f"Gain    : ×{python_time / cpp_time:.1f}")

print("\n\n")