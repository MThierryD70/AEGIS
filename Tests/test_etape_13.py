from aegis.config.manager import Config
from aegis.logger.logger import setup_logger
from aegis.db.signature_db import SignatureDB
from aegis.detection.bloom_matcher_cpp import BloomMatcher

print("\n\n")
config = Config.from_yaml("config.yaml")
setup_logger(config)

db = SignatureDB(config.database.path)
matcher = BloomMatcher(db)

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


print("\n\n")
# Test 1 — détection EICAR
result = matcher.check({"sha256": EICAR_SHA256})
print(f"EICAR détecté  : {result.is_threat}")
print(f"Malware        : {result.malware_name}")

print("\n")
# Test 2 — hash inconnu
result2 = matcher.check({"sha256": "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"})
print(f"Inconnu        : {result2.is_threat}")  # False

print("\n")
# Test 3 — performance Bloom vs SQLite direct
import time
from aegis.detection.signature_matcher import SignatureMatcher

sqlite_matcher = SignatureMatcher(db)
hashes_test = {"sha256": "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"}

start = time.perf_counter()
for _ in range(10000):
    sqlite_matcher.check(hashes_test)
sqlite_time = time.perf_counter() - start

start = time.perf_counter()
for _ in range(10000):
    matcher.check(hashes_test)
bloom_time = time.perf_counter() - start
print("\n\n")
print(f"\nSQLite direct  : {sqlite_time:.3f}s")
print(f"Bloom Filter   : {bloom_time:.3f}s")
print(f"Gain           : ×{sqlite_time / bloom_time:.1f}")

print("\n\n")







