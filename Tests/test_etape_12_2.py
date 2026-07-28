from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.scanner.hasher_cpp import HashCalculatorCpp, _lib
from pathlib import Path
print("\n\n")
config = Config.from_yaml("config.yaml")
setup_logger(config)

print("\n\n")
# Test 1 — la DLL est bien chargée
print(f"DLL chargée : {_lib is not None}")

print("\n\n")
# Test 2 — hash EICAR correct
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
result = HashCalculatorCpp.compute(Path("aa_test/eicar.com"))
print(f"EICAR validé : {result['sha256'] == EICAR_SHA256}")

print("\n\n")
# Test 3 — plus aucun message "DLL non disponible"
print(f"MD5    : {result['md5']}")
print(f"SHA256 : {result['sha256'][:32]}...")
print("\n\n")