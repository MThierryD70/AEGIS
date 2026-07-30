
import sys
sys.path.insert(0, "cpp/bin")

import aegis_cpp

print("\n\n")
print(f"Module : {aegis_cpp.__doc__}")

print("\n\n")
# Test hashing
from pathlib import Path
result = aegis_cpp.compute_hashes(str(Path("aa_test/eicar.com").resolve()))
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
print(f"EICAR validé : {result['sha256'] == EICAR_SHA256}")

print("\n\n")
# Test Bloom Filter
aegis_cpp.bloom_init()
aegis_cpp.bloom_add(EICAR_SHA256)
print(f"EICAR dans bloom   : {aegis_cpp.bloom_check(EICAR_SHA256)}")
print(f"Inconnu dans bloom : {aegis_cpp.bloom_check('aabbccdd')}")
print(f"Bits actifs        : {aegis_cpp.bloom_bit_count()}")


print("\n\n")
