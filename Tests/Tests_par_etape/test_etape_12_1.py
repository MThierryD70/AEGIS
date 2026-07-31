from pathlib import Path
from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.scanner.hasher import HashCalculator
from aegis.scanner.hasher_cpp import HashCalculatorCpp

print("\n\n")
config = Config.from_yaml("config.yaml")
setup_logger(config)

path = Path("aa_test/eicar.com")

print("\n\n")
# Test 1 — résultats C++ vs Python (doivent être identiques)
result_python = HashCalculator.compute(path)
result_cpp    = HashCalculatorCpp.compute(path)

print(f"Python MD5    : {result_python['md5']}")
print(f"C++    MD5    : {result_cpp['md5']}")
print(f"MD5 identique : {result_python['md5'] == result_cpp['md5']}")

print("\n")
print(f"Python SHA256 : {result_python['sha256']}")
print(f"C++    SHA256 : {result_cpp['sha256']}")
print(f"SHA256 identique : {result_python['sha256'] == result_cpp['sha256']}")


print("\n\n")
# Test 2 — le SHA256 EICAR doit toujours être correct
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
print(f"EICAR validé : {result_cpp['sha256'] == EICAR_SHA256}")
print("\n\n")
