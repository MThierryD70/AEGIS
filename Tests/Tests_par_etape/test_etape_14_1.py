import sys

print("\n\n")

# Ajoute cpp/bin au chemin de recherche des modules Python
sys.path.insert(0, "cpp/bin")

# Importe le module C++
import aegis_cpp

print("\n")
# Test 1 — vérifie que le module est bien chargé
print(f"Module chargé : {aegis_cpp.__doc__}")

print("\n\n")
# Test 2 — hashing
from pathlib import Path
result = aegis_cpp.compute_hashes(str(Path("aa_test/eicar.com").resolve()))
print(f"MD5    : {result['md5']}")
print(f"SHA256 : {result['sha256']}")

print("\n")
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
print(f"EICAR validé : {result['sha256'] == EICAR_SHA256}")


print("\n\n")
# Test 3 — Bloom Filter
aegis_cpp.bloom_init()
aegis_cpp.bloom_add(EICAR_SHA256)
print(f"EICAR dans bloom   : {aegis_cpp.bloom_check(EICAR_SHA256)}")
print(f"Inconnu dans bloom : {aegis_cpp.bloom_check('aabbccdd')}")
print(f"Bits actifs        : {aegis_cpp.bloom_bit_count()}")

print("\n\n")


